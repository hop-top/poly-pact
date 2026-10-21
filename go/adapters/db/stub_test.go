package db_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// adminStub is the red baseline of the database cases and the mutant of the
// profile's mutation rule: the broker a deployment gets by wiring PostgreSQL
// in the obvious way. It holds the pool administrator's credential and runs
// every query as that superuser, reading every column and filtering the rows
// in code by the mapped role and tenant; it verifies no connection and resets
// none. It maps the route with the generic route table, so it accepts any
// unreserved report id, a body, and any installed revision without a query
// entry. Its claims name the role it connects as, timed at the read; its
// check verifies by connecting and passes whenever the cluster answers; it
// allows every operation and declares no execution visibility.
type adminStub struct {
	st        dbState
	reg       []dbRecord
	srv       *fakeServer
	db        *sql.DB
	clk       clock.Clock
	hooks     *adaptertest.Hooks
	down      bool
	onExecute func()
}

// stubPasses are the database cases the stub passes: the controls of the
// mapping and a request that matches no route.
var stubPasses = map[string]bool{
	"DB-03.query-endpoint": true,
	"DB-03.sql-parameter":  true,
	"DB-04.at-limit":       true,
	"DB-04.in-grammar":     true,
}

var stubRoutes = []installed.Route{{Method: http.MethodGet, Path: "/api/v1/reports/{report_id}", Action: "report.read", Resource: "report:{report_id}"}}

// stubFactory builds the stub for a db/1 case; it realizes no other model.
func stubFactory(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != dbModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	st, err := parseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	s := newAdminStub(t, st, st.server(env.Hooks), st.Registry, env.Clock, st.down(sourceRegistry))
	return adaptertest.Subject{
		Adapter: s,
		Arrive:  func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error {
			return errors.New("stub: no credentials")
		},
	}, nil
}

func newAdminStub(t testing.TB, st dbState, srv *fakeServer, reg []dbRecord, clk clock.Clock, down bool) *adminStub {
	db := sql.OpenDB(srv.connector(adminRole, srv.roles[adminRole].Password))
	t.Cleanup(func() { _ = db.Close() })
	return &adminStub{st: st, reg: reg, srv: srv, db: db, clk: clk, hooks: srv.hooks, down: down}
}

// stubBrokerFactory is the stub as a broker of the unit tier.
func stubBrokerFactory(t testing.TB, w *unitWorld) (broker, error) {
	st := dbState{Model: dbModel, ClusterID: "northstar-reports", Gateway: dbGateway{TenantID: unitTenant, EnvironmentID: unitEnv, Origin: unitOrigin}}
	s := newAdminStub(t, st, w.srv, w.registry, clock.NewFake(w.now), w.registryDown)
	s.onExecute = w.onExecute
	return s, nil
}

func (s *adminStub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "postgresql", Version: "3.0", MappingRevision: "pact-db-1"}
}

func (s *adminStub) AuthenticateNative(context.Context, *http.Request) (adapter.Principal, error) {
	return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
}

func (s *adminStub) ResolveAgentBinding(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *adminStub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, version string) (core.OperationContext, error) {
	cfg := binding.Config{Origin: s.st.Gateway.Origin, HeaderAllowlist: s.st.Gateway.HeaderAllowlist, HeaderNormalizationID: "stub-1", MappingVersion: version, MaxBody: 1 << 20}
	return installed.MapRequest(cfg, stubRoutes, s.st.Gateway.EnvironmentID, r, p)
}

func (s *adminStub) record(principal string) (dbRecord, bool) {
	for _, r := range s.reg {
		if r.Principal == principal {
			return r, true
		}
	}
	return dbRecord{}, false
}

func (s *adminStub) ReadNativeClaim(_ context.Context, path string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	rec, _ := s.record(cc.Principal.ID)
	now := s.clk.Now()
	switch path {
	case pathRole:
		return adapter.NativeClaim{Value: "db:" + s.st.ClusterID + ":" + adminRole, ObservedAt: now, StatusCheckedAt: now, SourceID: sourceRegistry}, nil
	case pathTenant:
		return adapter.NativeClaim{Value: rec.TenantID, ObservedAt: now, StatusCheckedAt: now, SourceID: sourceRegistry}, nil
	}
	return adapter.NativeClaim{}, adapter.ErrUnsupportedRequirement
}

func (s *adminStub) CheckContext(ctx context.Context, _ string, _ adapter.CheckInput) adapter.CheckOutcome {
	if err := s.db.PingContext(ctx); err != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: sourceRegistry}
	}
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: installed.CodeRequirementSatisfied, SourceID: sourceRegistry, ObservedAt: s.clk.Now()}
}

func (s *adminStub) AuthorizeNative(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: "stub-policy"}, nil
}

func (s *adminStub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return adapter.NoVisibility{Reason: "the stub does not report"}, nil
}

// execute runs the report query as the pool administrator and keeps the rows
// whose tenant and permitted principal match the mapped role.
func (s *adminStub) execute(ctx context.Context, p adapter.Principal, op core.OperationContext) execution {
	rec, ok := s.record(p.ID)
	if !ok || s.down {
		rec = dbRecord{LoginRole: adminRole, TenantID: unitTenant}
	}
	id := ""
	if len(op.Resources) == 1 {
		_, id, _ = cut(op.Resources[0], "report:")
	}
	if s.onExecute != nil {
		s.onExecute()
	}
	s.hooks.Fire("execute")
	rows, err := s.db.QueryContext(ctx, sqlStub, id)
	if err != nil {
		return execution{err: err, kind: core.EventExecution, result: core.OutcomeFailure, dimension: core.DimensionNone}
	}
	defer func() { _ = rows.Close() }()
	var out [][]string
	for rows.Next() {
		var rid, body, tenant, permitted string
		if err := rows.Scan(&rid, &body, &tenant, &permitted); err != nil {
			return execution{err: err}
		}
		if permitted == rec.LoginRole && tenant == rec.TenantID {
			out = append(out, []string{rid, body})
		}
	}
	ex := execution{rows: out, sessionUser: adminRole, currentUser: adminRole, kind: core.EventExecution, result: core.OutcomeSuccess, dimension: core.DimensionReliability}
	if len(out) == 0 {
		ex.details = "empty"
	}
	return ex
}

func cut(s, prefix string) (before, after string, ok bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return "", s[len(prefix):], true
	}
	return s, "", false
}
