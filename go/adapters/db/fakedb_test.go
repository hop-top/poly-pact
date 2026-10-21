package db_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"hop.top/pact-go/adapter/adaptertest"
)

// The statements of profile section 3.2 (V1 to V3) and of the query registry
// entry (report.read, pact-db-1) of section 2, copied from the profile. The
// fake database answers these texts and no others, so a statement that
// differs by any octet is an unexpected statement (profile QB-5).
const (
	sqlV1 = "SELECT current_user, session_user, r.oid, r.rolsuper, r.rolbypassrls\n" +
		"FROM pg_catalog.pg_roles AS r\n" +
		"WHERE r.rolname = current_user;"
	sqlV2 = "SELECT count(*)\n" +
		"FROM pg_catalog.pg_roles AS r\n" +
		"WHERE r.rolname <> current_user\n" +
		"  AND (r.rolsuper OR r.rolbypassrls OR r.rolcanlogin)\n" +
		"  AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER');"
	sqlV3 = "SELECT c.relkind, c.relrowsecurity, c.relforcerowsecurity, o.rolname,\n" +
		"       pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER'),\n" +
		"       pg_catalog.has_table_privilege(c.oid, 'SELECT'),\n" +
		"       pg_catalog.has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')\n" +
		"FROM pg_catalog.pg_class AS c\n" +
		"JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace\n" +
		"JOIN pg_catalog.pg_roles AS o ON o.oid = c.relowner\n" +
		"WHERE n.nspname = $1 AND c.relname = $2;"
	sqlReport   = "SELECT report_id, body FROM public.customer_reports WHERE report_id = $1"
	sqlRollback = "ROLLBACK"
	sqlDiscard  = "DISCARD ALL"
	// sqlStub is the statement of the administrator stub: every column, so
	// that it can filter in code.
	sqlStub = "SELECT report_id, body, tenant_id, permitted_principal FROM public.customer_reports WHERE report_id = $1"
)

// writePrivileges are the privileges V3 requires to be absent (CV-4).
var writePrivileges = []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}

// fakeRole is a role of the fake cluster.
type fakeRole struct {
	Name      string
	OID       int64
	Super     bool
	BypassRLS bool
	Login     bool
	MemberOf  []string
	Password  string
}

// fakeTable is the protected table public.customer_reports.
type fakeTable struct {
	Schema, Name, Owner string
	Kind                string
	RLS, Force          bool
	// Grants maps a role name, or PUBLIC, to its privileges on the table.
	Grants map[string][]string
}

// fakePolicy is a SELECT policy of the sample I13 form: USING (tenant_id =
// Tenant AND permitted_principal = current_user), for the roles To.
type fakePolicy struct {
	To     []string
	Tenant string
}

type fakeRow struct{ ReportID, Tenant, Permitted, Body string }

// fakeEvent is one thing a client did on the fake cluster.
type fakeEvent struct {
	Conn int
	// Login is the role the connection authenticated as.
	Login string
	// Kind is connect, connect-refused, exec, query, prepare, stmt-query,
	// stmt-close or close.
	Kind string
	SQL  string
	Args []string
	// Returned lists the report ids of the rows sent to the client.
	Returned []string
	Err      string
}

// fakeServer is a PostgreSQL cluster as the verification statements and the
// registered statement see it: roles with their attributes and memberships,
// one protected table with its flags, grants and policies, and its rows. It
// records every connection and statement.
type fakeServer struct {
	mu       sync.Mutex
	roles    map[string]*fakeRole
	table    fakeTable
	policies []fakePolicy
	rows     []fakeRow
	log      []fakeEvent
	conns    int
	hooks    *adaptertest.Hooks

	// failDiscard makes DISCARD ALL fail.
	failDiscard bool
	// beforeReport runs when the registered statement arrives, before it is
	// evaluated: a change made by another session in the verification
	// window.
	beforeReport func(*fakeServer)
}

// i13Server is the cluster of sample I13 with a second principal: login roles
// report_maya and report_lee with SELECT on the table and a policy each; the
// owner report_admin, a NOLOGIN group report_readers, the superuser
// pact_admin; rows R-481 for report_maya, R-482 for report_lee, and R-483 of
// another tenant for report_maya.
func i13Server(hooks *adaptertest.Hooks) *fakeServer {
	s := &fakeServer{hooks: hooks, roles: map[string]*fakeRole{}}
	for _, r := range []*fakeRole{
		{Name: "pact_admin", OID: 10, Super: true, BypassRLS: true, Login: true, Password: "pact-admin-secret"},
		{Name: "report_admin", OID: 16384, Login: true, Password: "report-admin-secret"},
		{Name: "report_readers", OID: 16385},
		{Name: "report_maya", OID: 16390, Login: true, Password: "pg-pass-report-maya-5d1f9c"},
		{Name: "report_lee", OID: 16391, Login: true, Password: "pg-pass-report-lee-8a2e47"},
	} {
		s.roles[r.Name] = r
	}
	s.table = fakeTable{
		Schema: "public", Name: "customer_reports", Owner: "report_admin", Kind: "r", RLS: true, Force: true,
		Grants: map[string][]string{"report_maya": {"SELECT"}, "report_lee": {"SELECT"}},
	}
	s.policies = []fakePolicy{{To: []string{"report_maya"}, Tenant: "northstar"}, {To: []string{"report_lee"}, Tenant: "northstar"}}
	s.rows = []fakeRow{
		{ReportID: "R-481", Tenant: "northstar", Permitted: "report_maya", Body: "Northstar churn summary, Q3"},
		{ReportID: "R-482", Tenant: "northstar", Permitted: "report_lee", Body: "Lee pipeline review, Q3"},
		{ReportID: "R-483", Tenant: "harbor", Permitted: "report_maya", Body: "Harbor tenant ledger"},
	}
	return s
}

// events returns a copy of the log.
func (s *fakeServer) events() []fakeEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

// connections returns the number of connections opened.
func (s *fakeServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *fakeServer) record(e fakeEvent) {
	s.log = append(s.log, e)
}

// member reports whether role a is a member of role b, directly or
// indirectly; a role is a member of itself.
func (s *fakeServer) member(a, b string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(r string) bool {
		if r == b {
			return true
		}
		if seen[r] {
			return false
		}
		seen[r] = true
		if role := s.roles[r]; role != nil {
			for _, m := range role.MemberOf {
				if walk(m) {
					return true
				}
			}
		}
		return false
	}
	return walk(a)
}

// privilege reports whether role holds priv on the table: as its owner or a
// member of it, as a superuser, through a grant to itself, to a role it is a
// member of, or to PUBLIC.
func (s *fakeServer) privilege(role, priv string) bool {
	r := s.roles[role]
	if r == nil {
		return false
	}
	if r.Super || s.member(role, s.table.Owner) {
		return true
	}
	for grantee, privs := range s.table.Grants {
		if (grantee == "PUBLIC" || s.member(role, grantee)) && slices.Contains(privs, priv) {
			return true
		}
	}
	return false
}

// visible reports whether row is visible to role under row security.
func (s *fakeServer) visible(role string, row fakeRow) bool {
	r := s.roles[role]
	switch {
	case r == nil:
		return false
	case r.Super || r.BypassRLS, !s.table.RLS, role == s.table.Owner && !s.table.Force:
		return true
	}
	for _, p := range s.policies {
		applies := false
		for _, to := range p.To {
			if to == "PUBLIC" || s.member(role, to) {
				applies = true
			}
		}
		if applies && row.Tenant == p.Tenant && row.Permitted == role {
			return true
		}
	}
	return false
}

// sqlError is an error of the fake cluster with its SQLSTATE, the shape the
// pgx driver gives (pgconn.PgError.SQLState).
type sqlError struct{ code, msg string }

func (e *sqlError) Error() string    { return "ERROR: " + e.msg + " (SQLSTATE " + e.code + ")" }
func (e *sqlError) SQLState() string { return e.code }

// connector returns the connector of a login role with a password.
func (s *fakeServer) connector(role, password string) driver.Connector {
	return &fakeConnector{srv: s, role: role, password: password}
}

type fakeConnector struct {
	srv            *fakeServer
	role, password string
}

func (c *fakeConnector) Driver() driver.Driver { return fakeDriver{} }

func (c *fakeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := c.srv
	s.hooks.Fire("connect")
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.roles[c.role]
	if r == nil || !r.Login || r.Password == "" || r.Password != c.password {
		s.record(fakeEvent{Login: c.role, Kind: "connect-refused"})
		return nil, &sqlError{"28P01", "password authentication failed for user \"" + c.role + "\""}
	}
	s.conns++
	conn := &fakeConn{srv: s, id: s.conns, session: c.role, current: c.role, prepared: map[*fakeStmt]bool{}}
	s.record(fakeEvent{Conn: conn.id, Login: c.role, Kind: "connect"})
	return conn, nil
}

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fake driver: open by connector only")
}

// fakeConn is one session.
type fakeConn struct {
	srv      *fakeServer
	id       int
	session  string
	current  string
	prepared map[*fakeStmt]bool
	closed   bool
}

var (
	_ driver.Conn               = (*fakeConn)(nil)
	_ driver.ConnPrepareContext = (*fakeConn)(nil)
	_ driver.QueryerContext     = (*fakeConn)(nil)
	_ driver.ExecerContext      = (*fakeConn)(nil)
)

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *fakeConn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	s := c.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &fakeStmt{conn: c, query: query}
	c.prepared[st] = true
	s.record(fakeEvent{Conn: c.id, Login: c.session, Kind: "prepare", SQL: query})
	return st, nil
}

func (c *fakeConn) Close() error {
	s := c.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	if !c.closed {
		c.closed = true
		s.record(fakeEvent{Conn: c.id, Login: c.session, Kind: "close"})
	}
	return nil
}

func (c *fakeConn) Begin() (driver.Tx, error) {
	return nil, errors.New("fake driver: transactions are not used")
}

func (c *fakeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.run(ctx, "query", query, args)
}

func (c *fakeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	rows, err := c.run(ctx, "exec", query, args)
	if err != nil {
		return nil, err
	}
	_ = rows.Close()
	return driver.RowsAffected(0), nil
}

type fakeStmt struct {
	conn  *fakeConn
	query string
}

func (st *fakeStmt) Close() error {
	s := st.conn.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(st.conn.prepared, st)
	s.record(fakeEvent{Conn: st.conn.id, Login: st.conn.session, Kind: "stmt-close", SQL: st.query})
	return nil
}

func (st *fakeStmt) NumInput() int { return -1 }

func (st *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, errors.New("fake driver: Exec on a statement is not used")
}

func (st *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return st.QueryContext(context.Background(), named)
}

func (st *fakeStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	st.conn.srv.mu.Lock()
	live := st.conn.prepared[st]
	st.conn.srv.mu.Unlock()
	if !live {
		return nil, &sqlError{"26000", "prepared statement does not exist"}
	}
	return st.conn.run(ctx, "stmt-query", st.query, args)
}

// run evaluates one statement on the session.
func (c *fakeConn) run(ctx context.Context, kind, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := c.srv
	if query == sqlReport || query == sqlStub {
		s.mu.Lock()
		hook := s.beforeReport
		s.mu.Unlock()
		if hook != nil {
			hook(s)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := fakeEvent{Conn: c.id, Login: c.session, Kind: kind, SQL: query}
	for _, a := range args {
		ev.Args = append(ev.Args, fmt.Sprint(a.Value))
	}
	rows, err := c.evaluate(query, ev.Args)
	if err != nil {
		ev.Err = err.Error()
	}
	if rows != nil && (query == sqlReport || query == sqlStub) {
		for _, r := range rows.rows {
			ev.Returned = append(ev.Returned, r[0].(string))
		}
	}
	s.record(ev)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *fakeConn) evaluate(query string, args []string) (*fakeRows, error) {
	s := c.srv
	switch query {
	case sqlRollback:
		return &fakeRows{}, nil
	case sqlDiscard:
		if s.failDiscard {
			return nil, &sqlError{"08006", "connection failure"}
		}
		c.current = c.session
		clear(c.prepared)
		return &fakeRows{}, nil
	case sqlV1:
		out := &fakeRows{cols: []string{"current_user", "session_user", "oid", "rolsuper", "rolbypassrls"}}
		if r := s.roles[c.current]; r != nil {
			out.rows = append(out.rows, []driver.Value{c.current, c.session, r.OID, r.Super, r.BypassRLS})
		}
		return out, nil
	case sqlV2:
		var n int64
		for name, r := range s.roles {
			if name != c.current && (r.Super || r.BypassRLS || r.Login) && s.member(c.current, name) {
				n++
			}
		}
		return &fakeRows{cols: []string{"count"}, rows: [][]driver.Value{{n}}}, nil
	case sqlV3:
		out := &fakeRows{cols: []string{"relkind", "relrowsecurity", "relforcerowsecurity", "rolname", "pg_has_role", "has_table_privilege", "has_table_privilege"}}
		if len(args) != 2 {
			return nil, &sqlError{"08P01", "bind message supplies the wrong number of parameters"}
		}
		t := s.table
		if args[0] == t.Schema && args[1] == t.Name {
			write := false
			for _, p := range writePrivileges {
				write = write || s.privilege(c.current, p)
			}
			out.rows = append(out.rows, []driver.Value{t.Kind, t.RLS, t.Force, t.Owner, s.member(c.current, t.Owner), s.privilege(c.current, "SELECT"), write})
		}
		return out, nil
	case sqlReport, sqlStub:
		if len(args) != 1 {
			return nil, &sqlError{"08P01", "bind message supplies the wrong number of parameters"}
		}
		if !s.privilege(c.current, "SELECT") {
			return nil, &sqlError{"42501", "permission denied for table customer_reports"}
		}
		out := &fakeRows{cols: []string{"report_id", "body"}}
		if query == sqlStub {
			out.cols = []string{"report_id", "body", "tenant_id", "permitted_principal"}
		}
		for _, r := range s.rows {
			if r.ReportID != args[0] || !s.visible(c.current, r) {
				continue
			}
			row := []driver.Value{r.ReportID, r.Body}
			if query == sqlStub {
				row = append(row, r.Tenant, r.Permitted)
			}
			out.rows = append(out.rows, row)
		}
		return out, nil
	}
	return nil, &sqlError{"42601", "unexpected statement " + strings.SplitN(query, "\n", 2)[0]}
}

type fakeRows struct {
	cols []string
	rows [][]driver.Value
	i    int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}
