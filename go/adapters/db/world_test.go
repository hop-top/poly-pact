package db_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
)

// dbModel is the native-state model of the database cases
// (spec/v1.0/fixtures/adapters/db/README.md).
const dbModel = "db/1"

// sourceRegistry is the source id of the role and tenant registry.
const sourceRegistry = "role-registry"

// The approved native paths of F1 (profile section 2).
const (
	pathRole   = "/attributes/environment/database_role"
	pathTenant = "/attributes/environment/tenant_id"
)

// adminRole is the pool administrator of the fake cluster, a superuser; the
// broker must never connect as it.
const adminRole = "pact_admin"

func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }

// dbState is a db/1 native state.
type dbState struct {
	Model              string        `json:"model"`
	Gateway            dbGateway     `json:"gateway"`
	ClusterID          string        `json:"cluster_id"`
	Installed          []dbInstalled `json:"installed"`
	Registry           []dbRecord    `json:"registry"`
	Credentials        []dbSecret    `json:"credentials"`
	UnavailableSources []string      `json:"unavailable_sources"`
	Reporting          *dbReporting  `json:"reporting"`
}

type dbGateway struct {
	TenantID        string   `json:"tenant_id"`
	EnvironmentID   string   `json:"environment_id"`
	Origin          string   `json:"origin"`
	HeaderAllowlist []string `json:"header_allowlist"`
}

type dbInstalled struct {
	Revision string   `json:"revision"`
	Routes   []string `json:"routes"`
	Queries  []string `json:"queries"`
}

type dbRealm struct {
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
}

// dbRecord is a record of the role and tenant registry (profile RA-1).
type dbRecord struct {
	Realm         dbRealm `json:"realm"`
	Principal     string  `json:"principal"`
	LoginRole     string  `json:"login_role"`
	RoleOID       int64   `json:"role_oid"`
	CredentialRef string  `json:"credential_ref"`
	TenantID      string  `json:"tenant_id"`
	Revision      string  `json:"revision"`
	ChangedAt     int64   `json:"changed_at"`
}

type dbSecret struct {
	Ref    string `json:"ref"`
	Secret string `json:"secret"`
}

type dbReporting struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	KID      string `json:"kid"`
}

// modelOf returns the model member of a native state.
func modelOf(raw json.RawMessage) (string, error) {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("native state: %w", err)
	}
	return m.Model, nil
}

// parseState strict-parses a db/1 state.
func parseState(raw json.RawMessage) (dbState, error) {
	var st dbState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return dbState{}, fmt.Errorf("db/1 state: %w", err)
	}
	if st.Model != dbModel {
		return dbState{}, fmt.Errorf("db/1 state: model %q", st.Model)
	}
	if st.ClusterID == "" || st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "" {
		return dbState{}, errors.New("db/1 state: gateway and cluster_id are required")
	}
	for _, in := range st.Installed {
		for _, r := range in.Routes {
			if r != "R1" {
				return dbState{}, fmt.Errorf("db/1 state: route %q is not a route of the profile", r)
			}
		}
		for _, q := range in.Queries {
			if q != "report.read" {
				return dbState{}, fmt.Errorf("db/1 state: query %q is not an entry of the profile", q)
			}
		}
	}
	return st, nil
}

func (st dbState) down(source string) bool {
	for _, s := range st.UnavailableSources {
		if s == source {
			return true
		}
	}
	return false
}

func (st dbState) secret(ref string) (string, bool) {
	for _, c := range st.Credentials {
		if c.Ref == ref {
			return c.Secret, true
		}
	}
	return "", false
}

// server realizes the cluster of a db/1 state: the sample I13 cluster, whose
// login roles are those of the registry with the OIDs it records and the
// passwords of the secret store.
func (st dbState) server(hooks *adaptertest.Hooks) *fakeServer {
	s := i13Server(hooks)
	for _, rec := range st.Registry {
		r := s.roles[rec.LoginRole]
		if r == nil {
			r = &fakeRole{Name: rec.LoginRole, Login: true}
			s.roles[rec.LoginRole] = r
			s.table.Grants[rec.LoginRole] = []string{"SELECT"}
		}
		r.OID = rec.RoleOID
		if secret, ok := st.secret(rec.CredentialRef); ok {
			r.Password = secret
		}
	}
	return s
}

// The unit tier. A broker is an adapter under test with the execution path
// of profile section 3, row 5: it runs the registered statement of an
// admitted operation on a connection of the mapped role and reports what
// happened. The tests reach the database only through it.
type broker interface {
	adapter.Adapter
	execute(ctx context.Context, p adapter.Principal, op core.OperationContext) execution
}

// execution is what the broker reports for one operation.
type execution struct {
	rows [][]string
	// sessionUser and currentUser are the executor record: the V1 result
	// of the connection the statement ran on.
	sessionUser, currentUser string
	// kind, result, dimension and details are the outcome of profile RS-5.
	kind      core.EventKind
	result    core.OutcomeResult
	dimension core.Dimension
	details   string
	// mismatch is set for an error that is EXECUTOR_MISMATCH.
	mismatch bool
	// code is the draft 13.4 code of the error, when it carries one.
	code adapter.Code
	err  error
}

// unitWorld is the native state of a unit case: the cluster, the registry
// and the secret store.
type unitWorld struct {
	srv          *fakeServer
	hooks        *adaptertest.Hooks
	registry     []dbRecord
	registryDown bool
	secrets      map[string]string
	// onExecute runs where the broker sends the registered statement.
	onExecute func()
	now       time.Time
}

// brokerFactory builds the broker of a unit world.
type brokerFactory func(t testing.TB, w *unitWorld) (broker, error)

// Unit-tier identifiers.
const (
	unitTenant = "northstar"
	unitEnv    = "https://reports.northstar.example/environments/analytics"
	unitOrigin = "https://reports.northstar.example"
	unitMaya   = "https://idp.northstar.example/users/maya"
	unitLee    = "https://idp.northstar.example/users/lee"
	unitNow    = 1792080000
)

var unitRealm = adapter.Realm{TenantID: unitTenant, EnvironmentID: unitEnv}

// newUnitWorld is the sample I13 cluster with maya mapped to report_maya
// and lee to report_lee.
func newUnitWorld() *unitWorld {
	hooks := &adaptertest.Hooks{}
	w := &unitWorld{
		srv:   i13Server(hooks),
		hooks: hooks,
		registry: []dbRecord{
			{Realm: dbRealm(unitRealm), Principal: unitMaya, LoginRole: "report_maya", RoleOID: 16390, CredentialRef: "secret-store:report_maya", TenantID: "northstar", Revision: "role-registry-r3", ChangedAt: unitNow - 10000},
			{Realm: dbRealm(unitRealm), Principal: unitLee, LoginRole: "report_lee", RoleOID: 16391, CredentialRef: "secret-store:report_lee", TenantID: "northstar", Revision: "role-registry-r3", ChangedAt: unitNow - 10000},
		},
		secrets: map[string]string{
			"secret-store:report_maya": "pg-pass-report-maya-5d1f9c",
			"secret-store:report_lee":  "pg-pass-report-lee-8a2e47",
		},
		now: time.Unix(unitNow, 0),
	}
	return w
}

// principalOf is the authenticated principal of an id in the unit realm.
func principalOf(id string) adapter.Principal {
	return adapter.Principal{
		ID: id, Realm: unitRealm, Workload: "https://idp.northstar.example/clients/analytics-assistant",
		Mechanism: "oauth", AuthenticatedAt: time.Unix(unitNow, 0),
	}
}

// reportRequest is GET /api/v1/reports/{id}, the request target as written.
func reportRequest(rawID string) *http.Request {
	target := unitOrigin + "/api/v1/reports/" + rawID
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	r := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host, Header: http.Header{}, RequestURI: target, Body: http.NoBody}
	return r.WithContext(context.Background())
}

// mapReport maps the report request of a principal under pact-db-1.
func mapReport(b broker, principal, rawID string) (core.OperationContext, error) {
	return b.MapOperation(context.Background(), reportRequest(rawID), principalOf(principal), "pact-db-1")
}

// short is the first line of a statement.
func short(sql string) string {
	line, _, _ := strings.Cut(sql, "\n")
	return line
}
