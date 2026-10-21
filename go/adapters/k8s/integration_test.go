package k8s_test

import (
	"context"
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/k8s"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// The environment of the integration test against a real cluster, such as a
// kind cluster: the API server URL, a bearer token, and the PEM file of the
// API server's certificate authority. The token's account needs
// subjectaccessreviews create and selfsubjectreviews create (the ClusterRole
// system:auth-delegator covers the first), and the objects of
// spec/v1.0/fixtures/adapters/k8s/assets/rbac.yaml must be applied, with the
// service account operations/release-observer.
const (
	envServer = "PACT_TEST_K8S_SERVER"
	envToken  = "PACT_TEST_K8S_TOKEN"
	envCA     = "PACT_TEST_K8S_CA"
)

// TestIntegrationCluster runs against the cluster the environment names and
// is skipped when any of the three variables is unset: the self-review of the
// token names a user, the API server allows release-observer the list of
// row R1 under the Role of example I10, and denies it to an account the
// RoleBinding does not name.
func TestIntegrationCluster(t *testing.T) {
	server, token, caFile := os.Getenv(envServer), os.Getenv(envToken), os.Getenv(envCA)
	if server == "" || token == "" || caFile == "" {
		t.Skipf("set %s, %s and %s to run against a cluster", envServer, envToken, envCA)
	}
	fsys, err := adaptertest.DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(fsys, "adapters/k8s/assets/rbac.yaml"); err != nil {
		t.Fatalf("the RBAC asset: %v", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no certificate", caFile)
	}
	ctx := context.Background()

	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	ex, err := k8s.NewExecutor(k8s.ExecutorConfig{ClusterID: "kind", APIServer: server, RootCAs: roots, TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	info, err := ex.SelfReview(ctx)
	if err != nil || info.Username == "" {
		t.Fatalf("self-review: %+v, %v", info, err)
	}

	clk := clock.NewFake(time.Now())
	realm := adapter.Realm{TenantID: "integration", EnvironmentID: "https://gateway.example/environments/kind"}
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{TenantID: realm.TenantID, EnvironmentID: realm.EnvironmentID, Origin: "https://gateway.example"}}, clk)
	if err != nil {
		t.Fatal(err)
	}
	accounts := []k8s.Account{
		{Namespace: "operations", Name: "release-observer", UID: "integration-observer"},
		{Namespace: "operations", Name: "not-bound", UID: "integration-other"},
	}
	a, err := k8s.New(k8s.Config{
		Realm: realm, ClusterID: "kind", APIServer: server, RootCAs: roots,
		GatewayAudience: "https://gateway.example", Namespaces: []string{"operations"}, Accounts: accounts,
		GatewayToken: func(context.Context) (string, error) { return token, nil },
		Origin:       "https://gateway.example", Registry: referenceRegistry{ref}, Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		acct k8s.Account
		want adapter.Effect
	}{{accounts[0], adapter.EffectAllow}, {accounts[1], adapter.EffectDeny}} {
		id := k8s.Identifier("kind", c.acct.Namespace, c.acct.Name)
		p := adapter.Principal{
			ID: id, Workload: adapter.Workload(id), Realm: realm, Mechanism: k8s.Mechanism,
			Attributes: map[string]any{k8s.AttrK8s: map[string]any{
				"cluster_id": "kind", "namespace": c.acct.Namespace, "name": c.acct.Name, "uid": c.acct.UID,
				"groups":    []any{"system:serviceaccounts", "system:serviceaccounts:" + c.acct.Namespace, "system:authenticated"},
				"issued_at": clk.Now().Unix(), "reviewed_at": clk.Now().Unix(),
			}},
		}
		op := core.OperationContext{PrincipalID: id, Action: k8s.ActionList, Resources: []string{k8s.ResourceBase("kind")}}
		d, err := a.AuthorizeNative(ctx, p, op)
		if err != nil || d.Effect != c.want || d.SourceID != k8s.SourceAPIServer {
			t.Errorf("%s: %+v, %v; want %s from the API server", c.acct.Name, d, err, c.want)
		}
	}
}
