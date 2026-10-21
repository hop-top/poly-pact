package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// The verification statements of profile section 3.2, part of mapping
// revision pact-db-1. They are sent exactly as written there.
const (
	// StatementV1 reads the connection role (CV-1).
	StatementV1 = "SELECT current_user, session_user, r.oid, r.rolsuper, r.rolbypassrls\n" +
		"FROM pg_catalog.pg_roles AS r\n" +
		"WHERE r.rolname = current_user;"
	// StatementV2 counts elevated or foreign memberships (CV-2).
	StatementV2 = "SELECT count(*)\n" +
		"FROM pg_catalog.pg_roles AS r\n" +
		"WHERE r.rolname <> current_user\n" +
		"  AND (r.rolsuper OR r.rolbypassrls OR r.rolcanlogin)\n" +
		"  AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER');"
	// StatementV3 reads a protected table's kind, row-security flags,
	// owner and privileges, with the schema as $1 and the table as $2
	// (CV-3, CV-4).
	StatementV3 = "SELECT c.relkind, c.relrowsecurity, c.relforcerowsecurity, o.rolname,\n" +
		"       pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER'),\n" +
		"       pg_catalog.has_table_privilege(c.oid, 'SELECT'),\n" +
		"       pg_catalog.has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')\n" +
		"FROM pg_catalog.pg_class AS c\n" +
		"JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace\n" +
		"JOIN pg_catalog.pg_roles AS o ON o.oid = c.relowner\n" +
		"WHERE n.nspname = $1 AND c.relname = $2;"
	// The reset of a connection on release (CR-3).
	statementRollback = "ROLLBACK"
	statementDiscard  = "DISCARD ALL"
)

// The errors of Execute besides the sentinels of package adapter.
var (
	// ErrExecutorMismatch: the connection's role is not the mapped login
	// role, or is elevated (CV-1 to CV-3): execution-identity-v1 FAIL with
	// EXECUTOR_MISMATCH (CV-7).
	ErrExecutorMismatch = errors.New("db: the connection role is not the mapped login role (" + CodeExecutorMismatch + ")")
	// ErrExecutionCondition: a protected table is not an ordinary table
	// with row security enabled and forced, or the role lacks SELECT or
	// holds a write privilege on it (CV-3, CV-4): a native execution
	// condition that does not hold, so nothing runs (draft 2.3).
	ErrExecutionCondition = errors.New("db: a native execution condition of a protected table does not hold")
	// ErrNativeDenial: the server refused the registered statement for lack
	// of privilege (SQLSTATE 42501): a native denial, final (RS-5).
	ErrNativeDenial = errors.New("db: the server denied the statement")
	// ErrAmbiguous: the statement was sent, and the connection failed or the
	// statement was cancelled before its result was read (class 08, 57014):
	// its outcome is unknown and it is not retried (RS-5).
	ErrAmbiguous = errors.New("db: the statement was sent and its outcome is unknown")
	// ErrStatement: the server refused the registered statement with
	// another error.
	ErrStatement = errors.New("db: the server refused the statement")
)

// SQLStateError is the error of a statement the server refused, with its
// SQLSTATE code and no message text: the code identifies the condition
// (profile RS-5), and the text may name private objects.
type SQLStateError struct {
	Code string
	kind error
}

func (e *SQLStateError) Error() string { return e.kind.Error() + " (SQLSTATE " + e.Code + ")" }

// Unwrap returns the kind: [ErrNativeDenial], [ErrAmbiguous] or
// [ErrStatement].
func (e *SQLStateError) Unwrap() error { return e.kind }

// ExecutorRecord is the V1 result of the connection that ran an operation:
// the actual connection role, the evidence of profile RS-6. It holds no
// credential and no row content.
type ExecutorRecord struct {
	ClusterID   string
	SessionUser string
	CurrentUser string
	RoleOID     uint32
	VerifiedAt  time.Time
}

// Identifier is the executor identifier of the record,
// db:{cluster-id}:{login-role}.
func (r ExecutorRecord) Identifier() string { return Identifier(r.ClusterID, r.CurrentUser) }

// Ref is a reference to the record for evidence_refs:
// db-executor:{cluster-id}:{login-role}:{oid}:{verified-at}, the
// verification time in Unix seconds.
func (r ExecutorRecord) Ref() string {
	return "db-executor:" + component(r.ClusterID) + ":" + component(r.CurrentUser) + ":" +
		strconv.FormatUint(uint64(r.RoleOID), 10) + ":" + strconv.FormatInt(r.VerifiedAt.Unix(), 10)
}

// Result is the result of an executed operation: the rows as PostgreSQL
// returned them, every column as text, and the executor record.
type Result struct {
	Columns  []string
	Rows     [][]string
	Executor ExecutorRecord
}

// Outcome is the outcome report fields of an execution (profile RS-5, draft
// 14.5).
type Outcome struct {
	EventKind core.EventKind
	Result    core.OutcomeResult
	Dimension core.Dimension
	Details   string
}

// OutcomeOf maps the result of Execute to the outcome of profile RS-5: rows
// are EXECUTION SUCCESS reliability; zero rows the same with details
// "empty"; a native denial AUTHORIZATION FAILURE none; an ambiguous outcome
// EXECUTION UNKNOWN none; every refusal before the statement, and any other
// error, EXECUTION FAILURE none. It never says whether a hidden row exists.
func OutcomeOf(res Result, err error) Outcome {
	switch {
	case err == nil && len(res.Rows) == 0:
		return Outcome{core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "empty"}
	case err == nil:
		return Outcome{core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, ""}
	case errors.Is(err, ErrNativeDenial):
		return Outcome{core.EventAuthorization, core.OutcomeFailure, core.DimensionNone, ""}
	case errors.Is(err, ErrAmbiguous):
		return Outcome{core.EventExecution, core.OutcomeUnknown, core.DimensionNone, ""}
	}
	return Outcome{core.EventExecution, core.OutcomeFailure, core.DimensionNone, ""}
}

// Execute runs the registered statement of an admitted operation for the
// original principal p, under the login role the registry maps to p, on a
// connection of that role's pool (profile section 3, row 5).
//
// Before any connection, the operation is re-derived under the installed
// revision (its route, action, resources and query registry entry) and the
// principal's record is read; a registry that cannot answer, a principal
// without a record and a role without a credential are
// [adapter.ErrDependencyUnavailable], and no connection is opened under any
// role (RA-5). On the acquired connection V1, V2 and V3 run first (CV-6); a
// failed verification is [ErrExecutorMismatch] or [ErrExecutionCondition],
// and the connection is closed, never returned to the pool (CV-7). Then the
// statement is prepared, executed once with the values bound as parameters
// (QB-3) and closed, and the rows are returned as the server sent them
// (RS-4). On release the connection is rolled back and reset with DISCARD
// ALL, and closed when either fails (CR-3, CR-4). Nothing is retried, under
// this or any other connection or role.
func (a *Adapter) Execute(ctx context.Context, p adapter.Principal, op core.OperationContext) (Result, error) {
	if err := live(ctx, "execute"); err != nil {
		return Result{}, err
	}
	if p.ID == "" || p.ID != op.PrincipalID || p.Realm != a.cfg.Realm || op.EnvironmentID != a.cfg.Realm.EnvironmentID {
		return Result{}, fmt.Errorf("db: execute: the principal or the environment differs from the operation's: %w", adapter.ErrContextMismatch)
	}
	q, args, err := a.bind(op)
	if err != nil {
		return Result{}, fmt.Errorf("db: execute: %w", err)
	}
	rec, err := a.lookup(ctx, p.Realm, p.ID)
	if err != nil {
		return Result{}, fmt.Errorf("db: execute: %w", err)
	}
	pool, err := a.pool(ctx, rec)
	if err != nil {
		return Result{}, fmt.Errorf("db: execute: %w", err)
	}
	actx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	conn, err := pool.Conn(actx)
	cancel()
	if err != nil {
		return Result{}, fmt.Errorf("db: execute: a connection of the mapped role cannot be opened: %w", adapter.ErrDependencyUnavailable)
	}
	exec, err := a.verify(ctx, conn, rec, q.Tables)
	if err != nil {
		discard(conn)
		return Result{}, fmt.Errorf("db: execute: %w", err)
	}
	res, err := a.run(ctx, conn, q, args)
	res.Executor = exec
	if errors.Is(err, ErrAmbiguous) {
		discard(conn)
		return res, fmt.Errorf("db: execute: %w", err)
	}
	a.release(ctx, conn)
	if err != nil {
		return res, fmt.Errorf("db: execute: %w", err)
	}
	return res, nil
}

// verify runs V1, V2 and V3 on the connection and applies CV-1 to CV-4.
func (a *Adapter) verify(ctx context.Context, conn *sql.Conn, rec RoleRecord, tables []Table) (ExecutorRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	unreadable := fmt.Errorf("the catalog cannot be read: %w", adapter.ErrDependencyUnavailable)

	var v1 []struct {
		current, session string
		oid              int64
		super, bypass    bool
	}
	if err := queryRows(ctx, conn, StatementV1, nil, func(rows *sql.Rows) error {
		var r struct {
			current, session string
			oid              int64
			super, bypass    bool
		}
		if err := rows.Scan(&r.current, &r.session, &r.oid, &r.super, &r.bypass); err != nil {
			return err
		}
		v1 = append(v1, r)
		return nil
	}); err != nil {
		return ExecutorRecord{}, unreadable
	}
	if len(v1) != 1 {
		return ExecutorRecord{}, fmt.Errorf("V1 returned %d rows: %w", len(v1), ErrExecutorMismatch)
	}
	r := v1[0]
	if r.current != rec.LoginRole || r.session != rec.LoginRole || r.oid != int64(rec.RoleOID) || r.super || r.bypass {
		return ExecutorRecord{}, fmt.Errorf("V1: %w", ErrExecutorMismatch)
	}
	exec := ExecutorRecord{ClusterID: rec.ClusterID, SessionUser: r.session, CurrentUser: r.current, RoleOID: rec.RoleOID, VerifiedAt: a.cfg.Clock.Now()}

	var counts []int64
	if err := queryRows(ctx, conn, StatementV2, nil, func(rows *sql.Rows) error {
		var n int64
		if err := rows.Scan(&n); err != nil {
			return err
		}
		counts = append(counts, n)
		return nil
	}); err != nil {
		return ExecutorRecord{}, unreadable
	}
	if len(counts) != 1 || counts[0] != 0 {
		return ExecutorRecord{}, fmt.Errorf("V2: the role is a member of an elevated or login role: %w", ErrExecutorMismatch)
	}

	for _, t := range tables {
		type v3row struct {
			kind                 string
			rls, force           bool
			owner                string
			ownerMember          bool
			canSelect, canModify bool
		}
		var v3 []v3row
		if err := queryRows(ctx, conn, StatementV3, []any{t.Schema, t.Name}, func(rows *sql.Rows) error {
			var row v3row
			var kind any
			if err := rows.Scan(&kind, &row.rls, &row.force, &row.owner, &row.ownerMember, &row.canSelect, &row.canModify); err != nil {
				return err
			}
			row.kind = relkind(kind)
			v3 = append(v3, row)
			return nil
		}); err != nil {
			return ExecutorRecord{}, unreadable
		}
		switch {
		case len(v3) != 1:
			return ExecutorRecord{}, fmt.Errorf("V3 for %s.%s returned %d rows: %w", t.Schema, t.Name, len(v3), ErrExecutionCondition)
		case v3[0].owner == rec.LoginRole || v3[0].ownerMember:
			return ExecutorRecord{}, fmt.Errorf("V3: the role owns %s.%s or is a member of its owner: %w", t.Schema, t.Name, ErrExecutorMismatch)
		case v3[0].kind != "r" || !v3[0].rls || !v3[0].force:
			return ExecutorRecord{}, fmt.Errorf("V3: %s.%s is not an ordinary table with row security enabled and forced: %w", t.Schema, t.Name, ErrExecutionCondition)
		case !v3[0].canSelect || v3[0].canModify:
			return ExecutorRecord{}, fmt.Errorf("V3: the role lacks SELECT or holds a write privilege on %s.%s: %w", t.Schema, t.Name, ErrExecutionCondition)
		}
	}
	return exec, nil
}

// relkind normalizes the "char" value of pg_class.relkind as a driver
// returns it.
func relkind(v any) string {
	switch k := v.(type) {
	case string:
		return k
	case []byte:
		return string(k)
	case int64:
		return string(rune(k))
	}
	return ""
}

// queryRows runs a verification statement and passes each row to f.
func queryRows(ctx context.Context, conn *sql.Conn, text string, args []any, f func(*sql.Rows) error) error {
	rows, err := conn.QueryContext(ctx, text, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := f(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// run prepares the registered statement, executes it once and closes it.
func (a *Adapter) run(ctx context.Context, conn *sql.Conn, q Query, args []any) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	stmt, err := conn.PrepareContext(ctx, q.Text)
	if err != nil {
		return Result{}, fmt.Errorf("the statement cannot be prepared: %w", adapter.ErrDependencyUnavailable)
	}
	defer func() { _ = stmt.Close() }()
	if a.cfg.OnExecute != nil {
		a.cfg.OnExecute()
	}
	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	res := Result{Columns: cols}
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return Result{}, classify(ctx, err)
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		res.Rows = append(res.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return Result{}, classify(ctx, err)
	}
	return res, nil
}

// classify maps an error of the sent statement by its SQLSTATE code, never
// by its text (RS-5): 42501 is a native denial, class 08 and 57014 an
// ambiguous outcome, and so is an error without a code, such as a broken
// connection or an expired deadline.
func classify(ctx context.Context, err error) error {
	var se interface{ SQLState() string }
	if !errors.As(err, &se) || ctx.Err() != nil {
		return &SQLStateError{Code: "", kind: ErrAmbiguous}
	}
	code := se.SQLState()
	switch {
	case code == "42501":
		return &SQLStateError{Code: code, kind: ErrNativeDenial}
	case strings.HasPrefix(code, "08"), code == "57014":
		return &SQLStateError{Code: code, kind: ErrAmbiguous}
	}
	return &SQLStateError{Code: code, kind: ErrStatement}
}

// release rolls the connection back and resets it with DISCARD ALL before
// it returns to the pool; a connection whose reset fails, or does not
// complete in time, is closed (CR-3, CR-4). The reset runs even when ctx is
// done.
func (a *Adapter) release(ctx context.Context, conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.Timeout)
	defer cancel()
	for _, s := range []string{statementRollback, statementDiscard} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			discard(conn)
			return
		}
	}
	_ = conn.Close()
}

// discard closes the connection without returning it to the pool: the
// driver connection is marked bad, which database/sql closes.
func discard(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}
