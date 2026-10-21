package k8s_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/k8s"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
)

// k8sFactory builds the Kubernetes adapter for a case: from the k8s/1 state
// of a Kubernetes case or from the common/1 state of a common case. The
// fixtures realize the API server and the gateway's configuration; the
// adapter is the package's.
func k8sFactory(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case k8sModel:
		w, err := loadWorld(tb, env.State, env.Clock.Now())
		if err != nil {
			return adaptertest.Subject{}, err
		}
		ref, err := memory.New(w.enrollmentState(), env.Clock)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return worldSubject(tb, w, k8s.Config{Registry: referenceRegistry{ref}, Clock: env.Clock})
	case memory.Model:
		return commonSubject(tb, env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// enrollmentState is the common/1 state of the enrollments of a k8s/1 world,
// for the reference enrollment source.
func (w *world) enrollmentState() memory.State {
	return memory.State{
		Model:              memory.Model,
		Gateway:            w.st.Gateway,
		Enrollments:        w.st.Enrollments,
		UnavailableSources: w.st.UnavailableSources,
	}
}

// roots trusts the world's API server.
func (w *world) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(w.server.Certificate())
	return pool
}

// worldSubject builds the adapter of a world: its cluster entry, accounts,
// gateway token and executors, with the deployment parts of cfg.
func worldSubject(tb testing.TB, w *world, cfg k8s.Config) (adaptertest.Subject, error) {
	cfg.Realm = adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID}
	cfg.ClusterID = w.st.Cluster.ClusterID
	cfg.APIServer = w.apiServer()
	cfg.RootCAs = w.roots()
	cfg.GatewayAudience = w.st.Cluster.GatewayAudience
	cfg.Namespaces = w.st.Cluster.Namespaces
	for _, acct := range w.st.Accounts {
		cfg.Accounts = append(cfg.Accounts, k8s.Account{Namespace: acct.Namespace, Name: acct.Name, UID: acct.UID})
	}
	token := w.st.GatewayAccount.Token
	cfg.GatewayToken = func(context.Context) (string, error) { return token, nil }
	if b := w.st.ReviewBound; b != nil {
		cfg.ReviewBound = time.Duration(*b) * time.Second
	}
	if p := w.st.PreflightInterval; p != nil {
		cfg.PreflightInterval = time.Duration(*p) * time.Second
	}
	cfg.Origin = w.st.Gateway.Origin
	cfg.HeaderAllowlist = w.st.Gateway.HeaderAllowlist
	cfg.Executors = map[string]k8s.ExecutorSource{}
	for i, ex := range w.st.Executors {
		src, err := w.executor(tb, i, ex)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		cfg.Executors[ex.Account.Namespace+"/"+ex.Account.Name] = src
	}
	a, err := k8s.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{Adapter: a, Arrive: k8s.Mark, Credential: w.Credential}, nil
}

// executor realizes an executor of the state: the package's Executor over a
// token file in a temporary directory, absent when the state gives no token,
// reporting the credential kinds of the state.
func (w *world) executor(tb testing.TB, i int, ex executorState) (k8s.ExecutorSource, error) {
	file := filepath.Join(tb.TempDir(), fmt.Sprintf("token-%d", i))
	if ex.Token != nil {
		if err := os.WriteFile(file, []byte(*ex.Token), 0o600); err != nil {
			return nil, err
		}
	}
	e, err := k8s.NewExecutor(k8s.ExecutorConfig{
		ClusterID: w.st.Cluster.ClusterID, APIServer: w.apiServer(), RootCAs: w.roots(), TokenFile: file,
	})
	if err != nil {
		return nil, err
	}
	kinds := make([]k8s.CredentialKind, 0, len(ex.Credentials))
	for _, k := range ex.Credentials {
		kinds = append(kinds, k8s.CredentialKind(k))
	}
	return reportedExecutor{Executor: e, kinds: kinds}, nil
}

// reportedExecutor is an executor that reports the credential kinds of the
// state, which a deployment's executor reports of itself.
type reportedExecutor struct {
	*k8s.Executor
	kinds []k8s.CredentialKind
}

func (e reportedExecutor) Credentials(context.Context) ([]k8s.CredentialKind, error) {
	return slices.Clone(e.kinds), nil
}

// The constants of the common/1 realization (Kubernetes cases README,
// section "Common cases").
const (
	commonCluster      = "common-cluster"
	commonNamespace    = "common"
	commonGatewayToken = "common-gateway-token"
)

// commonUID is the uid the common/1 realization derives from a name: the
// first 32 characters of the lower-case hexadecimal SHA-256 digest.
func commonUID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:32]
}

// commonToken is a compact JWS with the payload of the realization.
func commonToken(username, secret string, iat int64) (string, error) {
	enc := func(v any) (string, error) {
		raw, err := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw), err
	}
	h, err := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	p, err := enc(map[string]any{"iat": iat, "jti": secret, "sub": username})
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString([]byte("common-signature")), nil
}

// commonWorld realizes a common/1 state in k8s/1: one registered account,
// token, review and agent pod per identity in the namespace common of the
// cluster common-cluster, and no grant.
func commonWorld(tb testing.TB, st memory.State, now time.Time) (*world, error) {
	ks := k8sState{
		Model:          k8sModel,
		Gateway:        st.Gateway,
		Cluster:        clusterState{ClusterID: commonCluster, GatewayAudience: st.Gateway.Origin, Namespaces: []string{commonNamespace}},
		GatewayAccount: gatewayAccount{Token: commonGatewayToken},
		Enrollments:    st.Enrollments,
	}
	gwInfo, err := json.Marshal(map[string]any{
		"username": "system:serviceaccount:pact-system:gateway", "uid": commonUID("gateway"),
		"groups": []string{"system:serviceaccounts", "system:serviceaccounts:pact-system", "system:authenticated"},
	})
	if err != nil {
		return nil, err
	}
	ks.SelfReviews = []selfReviewState{{Token: commonGatewayToken, UserInfo: gwInfo}}
	for _, id := range st.Identities {
		username := "system:serviceaccount:" + commonNamespace + ":" + id.Ref
		uid, pod := commonUID(id.Ref), id.Ref+"-agent"
		ks.Accounts = append(ks.Accounts, accountState{Namespace: commonNamespace, Name: id.Ref, UID: uid})
		tok, err := commonToken(username, id.Secret, now.Unix()-600)
		if err != nil {
			return nil, err
		}
		status, err := json.Marshal(map[string]any{
			"authenticated": true, "audiences": []string{st.Gateway.Origin},
			"user": map[string]any{
				"username": username, "uid": uid,
				"groups": []string{"system:serviceaccounts", "system:serviceaccounts:" + commonNamespace, "system:authenticated"},
				"extra":  map[string][]string{k8s.ExtraPodName: {pod}, k8s.ExtraPodUID: {commonUID(pod)}},
			},
		})
		if err != nil {
			return nil, err
		}
		ks.Tokens = append(ks.Tokens, tokenState{Ref: id.Ref, Token: tok, Reviews: []reviewState{{Audiences: []string{st.Gateway.Origin}, Status: status}}})
		p, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"name": pod, "namespace": commonNamespace, "uid": commonUID(pod)},
			"spec":     map[string]any{"serviceAccountName": id.Ref, "automountServiceAccountToken": false},
		})
		if err != nil {
			return nil, err
		}
		ks.Pods = append(ks.Pods, p)
	}
	return newWorld(tb, ks, now)
}

// commonSubject realizes a common/1 state: the identities as service
// accounts of commonWorld, and the claim sources, checks, mappings and signer
// of the state as the deployment's parts.
func commonSubject(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := commonWorld(tb, st, env.Clock.Now())
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	claims := map[string]installed.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]installed.InstalledCheck{}
	for _, c := range st.Checks {
		ic := installed.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &installed.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	var mappings map[string][]installed.Route
	if len(st.Mappings) > 0 {
		mappings = map[string][]installed.Route{}
		for _, m := range st.Mappings {
			for _, rt := range m.Routes {
				mappings[m.Version] = append(mappings[m.Version], installed.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
			}
		}
	}
	return worldSubject(tb, w, k8s.Config{
		Registry:         referenceRegistry{ref},
		Claims:           claims,
		Checks:           checks,
		Guard:            guard,
		Mappings:         mappings,
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	})
}

// referenceRegistry is the enrollment source of the records of a case: the
// lookup of the reference adapter over them, with dedicated workloads.
type referenceRegistry struct{ ref *memory.Adapter }

func (r referenceRegistry) Lookup(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	return r.ref.ResolveAgentBinding(ctx, realm, workload, agent)
}

func (referenceRegistry) Rotate(context.Context, enroll.Actor, string, core.Digest) error {
	return errors.New("the fixture registry is read-only")
}

func (referenceRegistry) MarkCompromised(context.Context, enroll.Actor, string) error {
	return errors.New("the fixture registry is read-only")
}

func unixTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
}

func reporting(r *memory.Reporting) (*installed.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &installed.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}

// commonClaims is the claim source of a common/1 state.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]installed.ClaimRecord, error) {
	var out []installed.ClaimRecord
	for _, r := range c.st.Claims {
		if r.Path != path || r.Principal != principal || r.Realm.TenantID != realm.TenantID || r.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		if slices.Contains(c.st.UnavailableSources, r.SourceID) {
			return nil, fmt.Errorf("source %s cannot answer: %w", r.SourceID, adapter.ErrDependencyUnavailable)
		}
		var v any
		if err := json.Unmarshal(r.Value, &v); err != nil {
			return nil, err
		}
		out = append(out, installed.ClaimRecord{
			Value: v, Resource: r.Resource, TaskID: r.TaskID,
			ObservedAt: unixTime(r.ObservedAt), StatusCheckedAt: unixTime(r.StatusCheckedAt),
			SourceID: r.SourceID, SourceRef: r.SourceRef,
		})
	}
	return out, nil
}

// commonCheck is an installed check of a common/1 state: its record, with the
// verdict of its native state.
type commonCheck struct {
	rec  memory.CheckRecord
	down bool
}

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (installed.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return installed.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return installed.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return installed.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}
