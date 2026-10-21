package db_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/db"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// envDSN names the PostgreSQL 16 server of the integration tier, as a
// connection string of an administrator that may create databases and
// roles. Without it the tier is skipped.
const envDSN = "PACT_TEST_PG_DSN"

// itDatabase is the database the tier creates, and drops first when a
// previous run left it.
const itDatabase = "pact_db_integration"

// itRoles are the roles the tier creates: report_maya by the asset, the
// others by the harness.
var itRoles = []string{"report_maya", "report_lee", "report_tableowner", "report_super", "report_bypass", "report_member", "report_writer", "report_revoke"}

// secretMap is a secret store over a map.
type secretMap map[string]string

func (m secretMap) Secret(_ context.Context, ref string) (string, error) {
	if s, ok := m[ref]; ok {
		return s, nil
	}
	return "", errors.New("no such credential")
}

// itRegistry is the role registry of the tier: principal to role.
type itRegistry struct {
	mu   sync.Mutex
	recs map[string]db.RoleRecord
}

func (r *itRegistry) Lookup(_ context.Context, _ adapter.Realm, principal string) (db.RoleRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.recs[principal]
	if !ok {
		return db.RoleRecord{}, db.ErrNoRecord
	}
	return rec, nil
}

// TestIntegration loads spec/v1.0/fixtures/adapters/db/schema.sql, the SQL of
// sample I13 verbatim, into a fresh database of the server at
// $PACT_TEST_PG_DSN as the administrator, adds what the sample leaves to
// native setup (the credentials, a second principal's role and policy, rows,
// and one role per refusal variant), and runs DB-01, DB-02, DB-05 to DB-07,
// DB-09 and DB-10 through the adapter with the pgx driver.
func TestIntegration(t *testing.T) {
	dsn := os.Getenv(envDSN)
	if dsn == "" {
		t.Skip(envDSN + " is not set; the integration tier needs a PostgreSQL 16 server")
	}
	ctx := context.Background()
	base, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("%s: %v", envDSN, err)
	}
	server := sql.OpenDB(stdlib.GetConnector(*base))
	t.Cleanup(func() { _ = server.Close() })
	exec := func(h *sql.DB, stmts ...string) {
		t.Helper()
		for _, s := range stmts {
			if _, err := h.ExecContext(ctx, s); err != nil {
				t.Fatalf("%s: %v", short(s), err)
			}
		}
	}
	var version string
	if err := server.QueryRowContext(ctx, "SHOW server_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("server_version %s", version)
	exec(server, "DROP DATABASE IF EXISTS "+itDatabase+" WITH (FORCE)")
	for _, r := range itRoles {
		exec(server, "DROP ROLE IF EXISTS "+r)
	}
	exec(server, "CREATE DATABASE "+itDatabase)
	t.Cleanup(func() {
		_, _ = server.ExecContext(ctx, "DROP DATABASE IF EXISTS "+itDatabase+" WITH (FORCE)")
		for _, r := range itRoles {
			_, _ = server.ExecContext(ctx, "DROP ROLE IF EXISTS "+r)
		}
	})
	cfg := base.Copy()
	cfg.Database = itDatabase
	admin := sql.OpenDB(stdlib.GetConnector(*cfg))
	t.Cleanup(func() { _ = admin.Close() })

	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	schema, err := fs.ReadFile(fsys, "adapters/db/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(admin, string(schema))

	secrets := secretMap{}
	pw := func(role string) string { return "it-" + role + "-7d3f" }
	exec(admin,
		"ALTER ROLE report_maya PASSWORD '"+pw("report_maya")+"'",
		"CREATE ROLE report_lee LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '"+pw("report_lee")+"'",
		"GRANT USAGE ON SCHEMA public TO report_lee",
		"GRANT SELECT ON public.customer_reports TO report_lee",
		"CREATE POLICY lee_report_read ON public.customer_reports FOR SELECT TO report_lee USING (tenant_id = 'northstar' AND permitted_principal = current_user)",
		"INSERT INTO public.customer_reports VALUES ('R-481', 'northstar', 'report_maya', 'Northstar churn summary, Q3'), ('R-482', 'northstar', 'report_lee', 'Lee pipeline review, Q3'), ('R-483', 'harbor', 'report_maya', 'Harbor tenant ledger')",
		// DB-02 variants: an owner, a superuser, a BYPASSRLS role, a member
		// of another login role, a role with a write privilege.
		"CREATE ROLE report_tableowner LOGIN PASSWORD '"+pw("report_tableowner")+"'",
		"CREATE ROLE report_super LOGIN SUPERUSER PASSWORD '"+pw("report_super")+"'",
		"CREATE ROLE report_bypass LOGIN BYPASSRLS PASSWORD '"+pw("report_bypass")+"'",
		"CREATE ROLE report_member LOGIN PASSWORD '"+pw("report_member")+"'",
		"GRANT report_lee TO report_member",
		"CREATE ROLE report_writer LOGIN PASSWORD '"+pw("report_writer")+"'",
		"CREATE ROLE report_revoke LOGIN PASSWORD '"+pw("report_revoke")+"'",
		"GRANT USAGE ON SCHEMA public TO report_tableowner, report_super, report_bypass, report_member, report_writer, report_revoke",
		"GRANT SELECT ON public.customer_reports TO report_bypass, report_member, report_writer, report_revoke",
		"GRANT INSERT ON public.customer_reports TO report_writer",
	)
	var adminUser string
	if err := admin.QueryRowContext(ctx, "SELECT current_user").Scan(&adminUser); err != nil {
		t.Fatal(err)
	}
	const cluster = "integration"
	reg := &itRegistry{recs: map[string]db.RoleRecord{}}
	principals := map[string]string{}
	for _, role := range itRoles {
		var oid int64
		if err := admin.QueryRowContext(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1", role).Scan(&oid); err != nil {
			t.Fatalf("oid of %s: %v", role, err)
		}
		principal := "https://idp.northstar.example/users/" + role
		principals[role] = principal
		secrets["secret-store:"+role] = pw(role)
		reg.recs[principal] = db.RoleRecord{ClusterID: cluster, LoginRole: role, RoleOID: uint32(oid), CredentialRef: "secret-store:" + role, TenantID: unitTenant, Revision: "integration-r1"}
	}
	var hookMu sync.Mutex
	var hook func()
	executions := 0
	a, err := db.New(db.Config{
		Realm: unitRealm, ClusterID: cluster, Origin: unitOrigin,
		Registry: reg,
		Dialer:   db.PostgreSQL{Config: cfg, Secrets: secrets},
		OnExecute: func() {
			hookMu.Lock()
			defer hookMu.Unlock()
			executions++
			if hook != nil {
				hook()
			}
		},
		Authenticator: noFrontDoor{}, Enrollments: noEnrollments{}, Permissions: noPolicy{},
		ExecutionVisible: true,
		Clock:            clock.NewFake(time.Unix(unitNow, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b := realBroker{a}
	run := func(role, id string) execution {
		t.Helper()
		op, err := mapReport(b, principals[role], id)
		if err != nil {
			t.Fatalf("map %s: %v", id, err)
		}
		return b.execute(ctx, principalOf(principals[role]), op)
	}
	success := func(t *testing.T, ex execution, role string, want [][]string) {
		t.Helper()
		var f failures
		checkSuccess(&f, "run", ex, nil, role, want)
		for _, m := range f {
			t.Error(m)
		}
	}

	t.Run("DB-01", func(t *testing.T) {
		for range 3 {
			success(t, run("report_maya", "R-481"), "report_maya", [][]string{rowMaya})
			success(t, run("report_lee", "R-482"), "report_lee", [][]string{rowLee})
		}
	})
	t.Run("DB-05", func(t *testing.T) {
		success(t, run("report_maya", "R-483"), "report_maya", nil)
	})
	t.Run("DB-06", func(t *testing.T) {
		success(t, run("report_maya", "R-999"), "report_maya", nil)
	})
	t.Run("DB-09", func(t *testing.T) {
		success(t, run("report_maya", "R-482"), "report_maya", nil)
		success(t, run("report_lee", "R-481"), "report_lee", nil)
	})
	t.Run("DB-10", func(t *testing.T) {
		c := cfg.Copy()
		c.User, c.Password = "report_maya", pw("report_maya")
		maya := sql.OpenDB(stdlib.GetConnector(*c))
		defer func() { _ = maya.Close() }()
		var kind any
		var rls, force, member, sel, write bool
		var owner string
		if err := maya.QueryRowContext(ctx, db.StatementV3, "public", "customer_reports").Scan(&kind, &rls, &force, &owner, &member, &sel, &write); err != nil {
			t.Fatal(err)
		}
		t.Logf("V3 as report_maya: relkind %T %v, relrowsecurity %v, relforcerowsecurity %v, owner %s, owner member %v, SELECT %v, write %v", kind, kind, rls, force, owner, member, sel, write)
		if fmt.Sprint(kind) != "r" && fmt.Sprint(kind) != "114" {
			t.Errorf("relkind %v, want r", kind)
		}
		if !rls || !force || owner != adminUser || member || !sel || write {
			t.Errorf("V3 conditions do not hold for the sample I13 table (CV-3, CV-4)")
		}
	})
	refused := func(role string, mismatch bool) func(*testing.T) {
		return func(t *testing.T) {
			hookMu.Lock()
			before := executions
			hookMu.Unlock()
			ex := run(role, "R-481")
			if ex.err == nil {
				t.Fatalf("executed as %s with rows %v; want a refusal before the statement", role, ex.rows)
			}
			if ex.mismatch != mismatch {
				t.Errorf("EXECUTOR_MISMATCH %v, want %v: %v", ex.mismatch, mismatch, ex.err)
			}
			if ex.kind != core.EventExecution || ex.result != core.OutcomeFailure || ex.dimension != core.DimensionNone {
				t.Errorf("outcome %s/%s/%s, want EXECUTION/FAILURE/none", ex.kind, ex.result, ex.dimension)
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			if executions != before {
				t.Errorf("the registered statement was sent")
			}
			t.Logf("%s: %v", role, ex.err)
		}
	}
	t.Run("DB-02.owner", func(t *testing.T) {
		exec(admin, "ALTER TABLE public.customer_reports OWNER TO report_tableowner")
		defer exec(admin, "ALTER TABLE public.customer_reports OWNER TO "+pgx.Identifier{adminUser}.Sanitize())
		refused("report_tableowner", true)(t)
	})
	t.Run("DB-02.superuser", refused("report_super", true))
	t.Run("DB-02.bypassrls", refused("report_bypass", true))
	t.Run("DB-02.login-member", refused("report_member", true))
	t.Run("DB-02.write-privilege", refused("report_writer", false))
	t.Run("DB-07", func(t *testing.T) {
		// The role reads once, so that its connection is open and pooled;
		// then SELECT is revoked on a second session after the statement
		// was prepared on the first and before it is executed.
		success(t, run("report_revoke", "R-481"), "report_revoke", nil)
		hookMu.Lock()
		before := executions
		var revokeErr error
		hook = func() {
			_, revokeErr = admin.ExecContext(ctx, "REVOKE SELECT ON public.customer_reports FROM report_revoke")
		}
		hookMu.Unlock()
		ex := run("report_revoke", "R-481")
		hookMu.Lock()
		hook = nil
		attempts := executions - before
		hookMu.Unlock()
		if revokeErr != nil {
			t.Fatalf("REVOKE: %v", revokeErr)
		}
		var se *db.SQLStateError
		code := ""
		if errors.As(ex.err, &se) {
			code = se.Code
		}
		t.Logf("statement after REVOKE on the open connection: %v (SQLSTATE %q)", ex.err, code)
		if ex.kind != core.EventAuthorization || ex.result != core.OutcomeFailure || ex.dimension != core.DimensionNone {
			t.Errorf("outcome %s/%s/%s, want AUTHORIZATION/FAILURE/none (RS-5): %v", ex.kind, ex.result, ex.dimension, ex.err)
		}
		if code != "42501" {
			t.Errorf("SQLSTATE %q, want 42501 insufficient_privilege", code)
		}
		if attempts != 1 {
			t.Errorf("%d statement attempts; want 1, no retry", attempts)
		}
		t.Run("before-acquisition", refused("report_revoke", false))
	})
}
