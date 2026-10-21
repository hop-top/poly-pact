package db_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
)

// The adapter under test: conformanceFactory realizes the db/1 cases and the
// common cases, unitBroker the unit tier.
var (
	conformanceFactory adaptertest.Factory = stubFactory
	unitBroker         brokerFactory       = stubBrokerFactory
)

// TestConformance runs the conformance suite, the common cases and the
// database cases of spec/v1.0/fixtures/adapters/db. No common case is replaced.
// The profile claims no shared workloads, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, conformanceFactory, adaptertest.Options{Adapter: "db"})
}

// TestStubFailsTheDBCases runs the database cases against the administrator
// stub: every case but those of stubPasses must fail, so that each case can
// catch the obvious wiring.
func TestStubFailsTheDBCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "db"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "DB-") {
			continue
		}
		seen++
		switch {
		case stubPasses[r.ID] && !r.Passed():
			t.Errorf("%s: the stub was expected to pass it: %v", r.ID, r.Failures)
		case !stubPasses[r.ID] && r.Passed():
			t.Errorf("%s: the stub passes it; the case cannot catch the stub", r.ID)
		}
	}
	if seen == 0 {
		t.Fatal("no database case loaded")
	}
}

// TestFixtureStates strict-parses the native state of every database case.
func TestFixtureStates(t *testing.T) {
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "db")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range cases {
		if !strings.HasPrefix(c.ID, "DB-") {
			continue
		}
		seen++
		if _, err := parseState(c.NativeState); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
	}
	if seen == 0 {
		t.Fatal("no database case loaded")
	}
}

// unitCase is one case of the unit tier: it builds its world, runs the
// broker and returns its failures.
type unitCase struct {
	id  string
	run func(t testing.TB, mk brokerFactory) []string
}

// TestUnit runs the unit tier against the broker of the package.
func TestUnit(t *testing.T) {
	for _, c := range unitCases {
		t.Run(c.id, func(t *testing.T) {
			for _, f := range c.run(t, unitBroker) {
				t.Error(f)
			}
		})
	}
}

// stubUnitPasses are the unit cases the administrator stub passes: the
// controls.
var stubUnitPasses = map[string]bool{
	"DB-02.group-member": true,
}

// TestStubFailsTheUnitCases is the mutation rule of the profile: a broker
// that queries as the pool administrator and filters in code fails DB-01,
// DB-02 and DB-05, and every other unit case but the controls.
func TestStubFailsTheUnitCases(t *testing.T) {
	required := map[string]bool{}
	for _, c := range unitCases {
		fails := c.run(t, stubBrokerFactory)
		switch {
		case stubUnitPasses[c.id] && len(fails) > 0:
			t.Errorf("%s: the stub was expected to pass it: %v", c.id, fails)
		case !stubUnitPasses[c.id] && len(fails) == 0:
			t.Errorf("%s: the stub passes it", c.id)
		}
		if len(fails) > 0 {
			required[strings.SplitN(c.id, ".", 2)[0]] = true
		}
	}
	for _, g := range []string{"DB-01", "DB-02", "DB-05"} {
		if !required[g] {
			t.Errorf("no %s case fails against the stub", g)
		}
	}
}

// failures collects the failures of a unit case.
type failures []string

func (f *failures) add(format string, args ...any) { *f = append(*f, fmt.Sprintf(format, args...)) }

// build makes the broker of w, failing the case when it cannot.
func build(t testing.TB, mk brokerFactory, w *unitWorld, f *failures) broker {
	b, err := mk(t, w)
	if err != nil {
		f.add("broker: %v", err)
		return nil
	}
	return b
}

// runReport maps and executes a report read of principal.
func runReport(b broker, principal, rawID string) (execution, error) {
	op, err := mapReport(b, principal, rawID)
	if err != nil {
		return execution{}, err
	}
	return b.execute(context.Background(), principalOf(principal), op), nil
}

// The expected statement sequence of one operation on one connection (CV-6,
// CR-3, QB-5): V1, V2, V3 for the protected table, the registered statement,
// the rollback and DISCARD ALL.
var operationSequence = []string{sqlV1, sqlV2, sqlV3, sqlReport, sqlRollback, sqlDiscard}

// sequences returns, per connection, the texts of the statements sent on it
// (a prepared statement counts once, at its execution).
func sequences(events []fakeEvent) map[int][]string {
	out := map[int][]string{}
	for _, e := range events {
		switch e.Kind {
		case "exec", "query", "stmt-query":
			out[e.Conn] = append(out[e.Conn], e.SQL)
		}
	}
	return out
}

// logins maps each connection to the role it authenticated as.
func logins(events []fakeEvent) map[int]string {
	out := map[int]string{}
	for _, e := range events {
		if e.Kind == "connect" {
			out[e.Conn] = e.Login
		}
	}
	return out
}

// checkClean fails on an unexpected statement, a refused connection, and a
// connection as the owner or the pool administrator.
func checkClean(f *failures, events []fakeEvent) {
	for _, e := range events {
		switch {
		case strings.Contains(e.Err, "unexpected statement"):
			f.add("unexpected statement on connection %d: %q (profile QB-5)", e.Conn, short(e.SQL))
		case e.Kind == "connect-refused":
			f.add("connection refused for %s", e.Login)
		case e.Kind == "connect" && (e.Login == adminRole || e.Login == "report_admin"):
			f.add("connection %d authenticated as %s, not a mapped login role (profile RA-5, B1)", e.Conn, e.Login)
		}
	}
}

// reportExecutions returns the executions of the registered statement.
func reportExecutions(events []fakeEvent) []fakeEvent {
	var out []fakeEvent
	for _, e := range events {
		if (e.Kind == "stmt-query" || e.Kind == "query" || e.Kind == "exec") && (e.SQL == sqlReport || e.SQL == sqlStub) {
			out = append(out, e)
		}
	}
	return out
}

// checkSuccess requires a successful execution with rows, run as role.
func checkSuccess(f *failures, label string, ex execution, err error, role string, want [][]string) {
	switch {
	case err != nil:
		f.add("%s: mapping: %v", label, err)
		return
	case ex.err != nil:
		f.add("%s: execution failed: %v", label, ex.err)
		return
	}
	if !slices.EqualFunc(ex.rows, want, slices.Equal) {
		f.add("%s: rows %v, want %v", label, ex.rows, want)
	}
	if ex.sessionUser != role || ex.currentUser != role {
		f.add("%s: executor record session_user %q current_user %q, want %q for both (CV-1)", label, ex.sessionUser, ex.currentUser, role)
	}
	wantDetails := ""
	if len(want) == 0 {
		wantDetails = "empty"
	}
	if ex.kind != core.EventExecution || ex.result != core.OutcomeSuccess || ex.dimension != core.DimensionReliability || ex.details != wantDetails {
		f.add("%s: outcome %s/%s/%s details %q, want EXECUTION/SUCCESS/reliability %q (RS-5)", label, ex.kind, ex.result, ex.dimension, ex.details, wantDetails)
	}
}

// checkRefused requires an execution refused before the registered
// statement, with the connection closed and never reused (CV-7).
func checkRefused(f *failures, label string, w *unitWorld, ex execution, err error, mismatch bool) {
	if err != nil {
		f.add("%s: mapping: %v", label, err)
		return
	}
	if ex.err == nil {
		f.add("%s: executed with rows %v; want a refusal before the statement (CV-7)", label, ex.rows)
	}
	if ex.mismatch != mismatch {
		f.add("%s: EXECUTOR_MISMATCH is %v, want %v (CV-7)", label, ex.mismatch, mismatch)
	}
	if ex.kind != core.EventExecution || ex.result != core.OutcomeFailure || ex.dimension != core.DimensionNone {
		f.add("%s: outcome %s/%s/%s, want EXECUTION/FAILURE/none (RS-5)", label, ex.kind, ex.result, ex.dimension)
	}
	events := w.srv.events()
	if n := len(reportExecutions(events)); n != 0 {
		f.add("%s: the registered statement was sent %d times; want none", label, n)
	}
	if slices.Contains(w.hooks.Fired(), "execute") {
		f.add("%s: the execute hook fired", label)
	}
	opened := map[int]bool{}
	for _, e := range events {
		if e.Kind == "connect" {
			opened[e.Conn] = true
		}
		if e.Kind == "close" {
			delete(opened, e.Conn)
		}
	}
	if len(opened) != 0 {
		f.add("%s: connections %v were not closed after the refusal (CV-7)", label, opened)
	}
	for c, seq := range sequences(events) {
		if slices.Contains(seq, sqlDiscard) {
			f.add("%s: connection %d was reset for reuse after the refusal; it must be closed (CV-7)", label, c)
		}
	}
}

var (
	rowMaya = []string{"R-481", "Northstar churn summary, Q3"}
	rowLee  = []string{"R-482", "Lee pipeline review, Q3"}
)

var unitCases = []unitCase{
	{"DB-01.sequence", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		runs := []struct {
			principal, id, role string
			want                [][]string
		}{
			{unitMaya, "R-481", "report_maya", [][]string{rowMaya}},
			{unitLee, "R-482", "report_lee", [][]string{rowLee}},
			{unitMaya, "R-481", "report_maya", [][]string{rowMaya}},
		}
		var roles []string
		for i, r := range runs {
			ex, err := runReport(b, r.principal, r.id)
			checkSuccess(&f, fmt.Sprintf("run %d", i+1), ex, err, r.role, r.want)
			roles = append(roles, r.role)
		}
		events := w.srv.events()
		checkClean(&f, events)
		login := logins(events)
		execs := reportExecutions(events)
		if len(execs) != len(runs) {
			f.add("%d executions of the registered statement for %d operations", len(execs), len(runs))
		} else {
			for i, e := range execs {
				if login[e.Conn] != roles[i] {
					f.add("run %d ran on connection %d of %s, want a connection of %s (CR-1)", i+1, e.Conn, login[e.Conn], roles[i])
				}
			}
		}
		for c, seq := range sequences(events) {
			n := len(operationSequence)
			if len(seq) == 0 || len(seq)%n != 0 {
				f.add("connection %d of %s sent %v, want repetitions of V1, V2, V3, the statement, ROLLBACK, DISCARD ALL", c, login[c], shorts(seq))
				continue
			}
			for i := 0; i < len(seq); i += n {
				if !slices.Equal(seq[i:i+n], operationSequence) {
					f.add("connection %d of %s sent %v for one operation, want V1, V2, V3, the statement, ROLLBACK, DISCARD ALL (CV-6, CR-3)", c, login[c], shorts(seq[i:i+n]))
				}
			}
		}
		return f
	}},
	{"DB-01.prepared-again", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		for i := range 2 {
			ex, err := runReport(b, unitMaya, "R-481")
			checkSuccess(&f, fmt.Sprintf("run %d", i+1), ex, err, "report_maya", [][]string{rowMaya})
		}
		events := w.srv.events()
		checkClean(&f, events)
		if n := w.srv.connections(); n != 1 {
			f.add("%d connections for two operations of one role; want the pooled connection reused after its reset (CR-1, CR-3)", n)
		}
		prepared := 0
		for _, e := range events {
			if e.Kind == "prepare" && e.SQL == sqlReport {
				prepared++
			}
		}
		if prepared != 2 {
			f.add("the registered statement was prepared %d times; want once per acquisition, since DISCARD ALL deallocates it (CR-5)", prepared)
		}
		return f
	}},
	{"DB-01.reset-fails", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		w.srv.failDiscard = true
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		for i := range 2 {
			ex, err := runReport(b, unitMaya, "R-481")
			checkSuccess(&f, fmt.Sprintf("run %d", i+1), ex, err, "report_maya", [][]string{rowMaya})
		}
		events := w.srv.events()
		closed := map[int]bool{}
		discards := 0
		for _, e := range events {
			if e.Kind == "close" {
				closed[e.Conn] = true
			}
			if e.SQL == sqlDiscard {
				discards++
			}
		}
		if discards == 0 {
			f.add("no DISCARD ALL was sent (CR-3)")
		}
		if n := w.srv.connections(); n != 2 || !closed[1] {
			f.add("%d connections, closed %v: a connection whose DISCARD ALL fails must be closed and never reused (CR-4)", n, closed)
		}
		return f
	}},
	{"DB-02.owner", db02(func(w *unitWorld) {
		w.registry[0].LoginRole, w.registry[0].RoleOID, w.registry[0].CredentialRef = "report_admin", 16384, "secret-store:report_admin"
		w.secrets["secret-store:report_admin"] = "report-admin-secret"
	}, true)},
	{"DB-02.superuser", db02(func(w *unitWorld) { w.srv.roles["report_maya"].Super = true }, true)},
	{"DB-02.bypassrls", db02(func(w *unitWorld) { w.srv.roles["report_maya"].BypassRLS = true }, true)},
	{"DB-02.owner-member", db02(func(w *unitWorld) { w.srv.roles["report_maya"].MemberOf = []string{"report_admin"} }, true)},
	{"DB-02.login-member", db02(func(w *unitWorld) { w.srv.roles["report_maya"].MemberOf = []string{"report_lee"} }, true)},
	{"DB-02.other-oid", db02(func(w *unitWorld) { w.registry[0].RoleOID = 16399 }, true)},
	{"DB-02.write-privilege", db02(func(w *unitWorld) {
		w.srv.table.Grants["report_maya"] = []string{"SELECT", "INSERT"}
	}, false)},
	{"DB-02.group-member", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		w.srv.roles["report_maya"].MemberOf = []string{"report_readers"}
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, unitMaya, "R-481")
		if err != nil || ex.err != nil {
			f.add("a member of a NOLOGIN group without elevated attributes is refused: %v %v (CV-2)", err, ex.err)
		}
		return f
	}},
	{"DB-03.constant-text", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, unitMaya, "R-481?sql=DELETE%20FROM%20public.customer_reports")
		checkSuccess(&f, "run", ex, err, "report_maya", [][]string{rowMaya})
		events := w.srv.events()
		checkClean(&f, events)
		for _, e := range reportExecutions(events) {
			if e.SQL != sqlReport || !slices.Equal(e.Args, []string{"R-481"}) {
				f.add("statement %q with %v; want the registry constant with [R-481] (QB-2, QB-6)", short(e.SQL), e.Args)
			}
		}
		for _, e := range events {
			if strings.Contains(e.SQL, "DELETE FROM") || slices.ContainsFunc(e.Args, func(a string) bool { return strings.Contains(a, "DELETE") }) {
				f.add("the query parameter reached the server: %q %v (RB-50)", short(e.SQL), e.Args)
			}
		}
		return f
	}},
	{"DB-04.bound", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, unitMaya, "R-481--")
		checkSuccess(&f, "run", ex, err, "report_maya", nil)
		events := w.srv.events()
		checkClean(&f, events)
		execs := reportExecutions(events)
		if len(execs) != 1 {
			f.add("%d executions of the registered statement, want 1", len(execs))
		}
		for _, e := range execs {
			if e.Kind != "stmt-query" || e.SQL != sqlReport || !slices.Equal(e.Args, []string{"R-481--"}) {
				f.add("%s %q with %v; want the prepared registry constant with the value as $1 (QB-3, QB-4)", e.Kind, short(e.SQL), e.Args)
			}
		}
		for _, e := range events {
			if strings.Contains(e.SQL, "R-481") {
				f.add("the value was concatenated into the statement: %q (QB-3)", short(e.SQL))
			}
		}
		return f
	}},
	{"DB-04.out-of-grammar", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		_, err := mapReport(b, unitMaya, "R-481'%20OR%20'1'='1")
		if code, _ := adapter.CodeOf(err); code != adapter.CodeInvalidMessage {
			f.add("mapping: %v; want INVALID_MESSAGE (QB-4)", err)
		}
		if n := w.srv.connections(); n != 0 {
			f.add("%d connections opened; want none", n)
		}
		return f
	}},
	{"DB-05.hidden", db05(unitMaya, "R-482")},
	{"DB-05.other-tenant", db05(unitMaya, "R-483")},
	{"DB-06.absent", db05(unitMaya, "R-999")},
	{"DB-07.revoked-in-window", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		w.srv.beforeReport = func(s *fakeServer) {
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.table.Grants, "report_maya")
		}
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, unitMaya, "R-481")
		switch {
		case err != nil:
			f.add("mapping: %v", err)
		case ex.err == nil:
			f.add("executed with rows %v after SELECT was revoked; want the native error", ex.rows)
		case ex.mismatch:
			f.add("a native privilege error reported as EXECUTOR_MISMATCH")
		}
		if ex.kind != core.EventAuthorization || ex.result != core.OutcomeFailure || ex.dimension != core.DimensionNone {
			f.add("outcome %s/%s/%s, want AUTHORIZATION/FAILURE/none (RS-5)", ex.kind, ex.result, ex.dimension)
		}
		events := w.srv.events()
		checkClean(&f, events)
		if n := len(reportExecutions(events)); n != 1 {
			f.add("the registered statement was sent %d times; want once, with no retry (RS-5, CV-7)", n)
		}
		if n := w.srv.connections(); n != 1 {
			f.add("%d connections; want no other connection after the native error", n)
		}
		return f
	}},
	{"DB-07.revoked-before", db02(func(w *unitWorld) { delete(w.srv.table.Grants, "report_maya") }, false)},
	{"DB-08.registry-down", db08(func(w *unitWorld) { w.registryDown = true })},
	{"DB-08.no-record", db08(func(w *unitWorld) { w.registry = w.registry[1:] })},
	{"DB-08.no-credential", db08(func(w *unitWorld) { delete(w.secrets, "secret-store:report_maya") })},
	{"DB-10.no-row-security", db02(func(w *unitWorld) { w.srv.table.RLS = false }, false)},
	{"DB-10.not-forced", db02(func(w *unitWorld) { w.srv.table.Force = false }, false)},
	{"DB-10.view", db02(func(w *unitWorld) { w.srv.table.Kind = "v" }, false)},
}

// db02 is a refusal case: the world change makes the connection fail its
// verification, with EXECUTOR_MISMATCH or as a native execution condition.
func db02(change func(*unitWorld), mismatch bool) func(testing.TB, brokerFactory) []string {
	return func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		change(w)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, unitMaya, "R-481")
		checkRefused(&f, "run", w, ex, err, mismatch)
		return f
	}
}

// db05 is an empty result: zero rows, the empty-result outcome, one
// statement and no row sent to the broker.
func db05(principal, id string) func(testing.TB, brokerFactory) []string {
	return func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, principal, id)
		checkSuccess(&f, "run", ex, err, "report_maya", nil)
		events := w.srv.events()
		checkClean(&f, events)
		execs := reportExecutions(events)
		if len(execs) != 1 {
			f.add("%d statements sent; want exactly the registered statement, no second query (QB-7, RS-3)", len(execs))
		}
		for _, e := range execs {
			if len(e.Returned) != 0 {
				f.add("the server sent the rows %v to the broker; a hidden row never leaves the server (RS-3, RS-4)", e.Returned)
			}
		}
		return f
	}
}

// db08 is a mapping that is unavailable: no connection under any role.
func db08(change func(*unitWorld)) func(testing.TB, brokerFactory) []string {
	return func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld()
		change(w)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		ex, err := runReport(b, unitMaya, "R-481")
		if err != nil {
			f.add("mapping: %v", err)
			return f
		}
		if ex.err == nil || ex.code != adapter.CodeDependencyUnavailable {
			f.add("execution: %v (code %q); want DEPENDENCY_UNAVAILABLE (RA-5)", ex.err, ex.code)
		}
		if ex.kind != core.EventExecution || ex.result != core.OutcomeFailure || ex.dimension != core.DimensionNone {
			f.add("outcome %s/%s/%s, want EXECUTION/FAILURE/none (RS-5)", ex.kind, ex.result, ex.dimension)
		}
		if n := w.srv.connections(); n != 0 || len(w.srv.events()) != 0 {
			f.add("%d connections, events %v; want none under any role (RA-5, B1)", n, w.srv.events())
		}
		return f
	}
}

func shorts(seq []string) []string {
	out := make([]string, len(seq))
	for i, s := range seq {
		out[i] = short(s)
	}
	return out
}
