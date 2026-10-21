package k8s

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// CredentialKind is a kind of credential an executor can hold (KR-11).
type CredentialKind string

// The credential kinds of KR-11. Only CredentialProjectedToken is allowed.
const (
	CredentialProjectedToken CredentialKind = "projected-token"
	CredentialKubeconfig     CredentialKind = "kubeconfig"
	CredentialTokenSecret    CredentialKind = "token-secret"
	CredentialClientCert     CredentialKind = "client-certificate"
	CredentialPlugin         CredentialKind = "credential-plugin"
	CredentialImpersonation  CredentialKind = "impersonation"
)

// ExecutorSource is the executor of one registered account as the check
// execution-identity-v1 consults it.
type ExecutorSource interface {
	// Credentials returns the kinds of credential the executor holds.
	Credentials(ctx context.Context) ([]CredentialKind, error)
	// SelfReview returns what a SelfSubjectReview made with the executor's
	// token reports [K3]. A missing or refused token is an error.
	SelfReview(ctx context.Context) (UserInfo, error)
}

// ErrNoToken is the error of an executor whose token cannot be read.
var ErrNoToken = errors.New("k8s: the executor's token cannot be read")

// ErrNativeDenial is the error of an executor request the API server refused
// with 403: a native denial, which is final and never retried (KR-12).
var ErrNativeDenial = errors.New("k8s: the API server denied the request")

// ErrContinuation is the error of a list answer that carries a continue
// token, which a translation row never asks for (KR-13).
var ErrContinuation = errors.New("k8s: the answer carries a continue token")

// ExecutorConfig configures the executor of one registered account. It has
// no field for any credential other than the projected token: a kubeconfig,
// a token Secret, a client certificate, a credential plugin or an
// impersonation header cannot be given to it (KR-11).
type ExecutorConfig struct {
	// ClusterID is the configured identifier of the cluster.
	ClusterID string
	// APIServer is the https URL of the pinned API server.
	APIServer string
	// RootCAs are the trust anchors of the API server's certificate.
	RootCAs *x509.CertPool
	// TokenFile is the path of the projected serviceAccountToken of the
	// executor's pod, read for each request so that the kubelet's refresh is
	// used [K4].
	TokenFile string
	// Timeout bounds each request. Zero is [DefaultTimeout].
	Timeout time.Duration
	// OnExecute, when set, is called just before a downstream request is
	// sent.
	OnExecute func()
}

// Executor sends the downstream requests of admitted operations under the
// registered account, with that pod's projected token and nothing else.
type Executor struct {
	cfg ExecutorConfig
	api *apiClient
}

var _ ExecutorSource = (*Executor)(nil)

// NewExecutor returns the executor of cfg.
func NewExecutor(cfg ExecutorConfig) (*Executor, error) {
	u, err := url.Parse(cfg.APIServer)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.TrimSuffix(u.Path, "/") != "" || u.RawQuery != "":
		return nil, fmt.Errorf("k8s: executor: the API server %q must be an https origin", cfg.APIServer)
	case cfg.RootCAs == nil:
		return nil, errors.New("k8s: executor: no trust anchors for the API server")
	case cfg.TokenFile == "":
		return nil, errors.New("k8s: executor: no projected token file (KR-11)")
	case cfg.ClusterID == "":
		return nil, errors.New("k8s: executor: no cluster id")
	case cfg.Timeout < 0:
		return nil, errors.New("k8s: executor: negative timeout")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Executor{cfg: cfg, api: newAPIClient(strings.TrimSuffix(cfg.APIServer, "/"), cfg.RootCAs, cfg.Timeout)}, nil
}

// Credentials reports the one credential kind an Executor can hold.
func (e *Executor) Credentials(context.Context) ([]CredentialKind, error) {
	return []CredentialKind{CredentialProjectedToken}, nil
}

func (e *Executor) token() (string, error) {
	raw, err := os.ReadFile(e.cfg.TokenFile)
	if err != nil {
		return "", ErrNoToken
	}
	t := strings.TrimSpace(string(raw))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", ErrNoToken
	}
	return t, nil
}

// SelfReview makes a SelfSubjectReview with the executor's token.
func (e *Executor) SelfReview(ctx context.Context) (UserInfo, error) {
	t, err := e.token()
	if err != nil {
		return UserInfo{}, fmt.Errorf("%w: %w", err, adapter.ErrDependencyUnavailable)
	}
	info, err := e.api.selfReview(ctx, t)
	if err != nil {
		return UserInfo{}, fmt.Errorf("k8s: executor: self-review: %w", adapter.ErrDependencyUnavailable)
	}
	return info, nil
}

// Path returns the downstream path of the translation row of an operation
// (KR-13): GET /apis/apps/v1/namespaces/operations/deployments for R1, and
// .../deployments/{name} for R2, with no query.
func (e *Executor) Path(op core.OperationContext) (string, bool) {
	const base = "/apis/apps/v1/namespaces/" + RowNamespace + "/deployments"
	switch op.Action {
	case ActionList:
		if len(op.Resources) == 1 && op.Resources[0] == ResourceBase(e.cfg.ClusterID) {
			return base, true
		}
	case ActionGet:
		if name, ok := rowName(e.cfg.ClusterID, op.Resources); ok {
			return base + "/" + name, true
		}
	}
	return "", false
}

// Execute sends the translation row's request of an admitted operation and
// returns the API server's JSON answer. The request carries only the
// executor's Authorization header and Accept: application/json, nothing
// copied from the client (KR-13). A 403 is [ErrNativeDenial], final; a list
// answer with a continue token is [ErrContinuation], and nothing more is
// fetched.
func (e *Executor) Execute(ctx context.Context, op core.OperationContext) (json.RawMessage, error) {
	path, ok := e.Path(op)
	if !ok {
		return nil, fmt.Errorf("k8s: executor: the operation has no translation row: %w", adapter.ErrUnsupportedRequirement)
	}
	t, err := e.token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", err, adapter.ErrDependencyUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.api.base+path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("k8s: executor: %w", adapter.ErrDependencyUnavailable)
	}
	req.Header.Set("Authorization", "Bearer "+t)
	req.Header.Set("Accept", "application/json")
	if e.cfg.OnExecute != nil {
		e.cfg.OnExecute()
	}
	resp, err := e.api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: executor: %w", adapter.ErrDependencyUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	switch {
	case err != nil || len(raw) > maxAnswer:
		return nil, fmt.Errorf("k8s: executor: %w", adapter.ErrDependencyUnavailable)
	case resp.StatusCode == http.StatusForbidden:
		return nil, ErrNativeDenial
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("k8s: executor: status %d: %w", resp.StatusCode, adapter.ErrDependencyUnavailable)
	}
	var list struct {
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
	}
	if decode(raw, &list) != nil {
		return nil, fmt.Errorf("k8s: executor: %w", adapter.ErrDependencyUnavailable)
	}
	if list.Metadata.Continue != "" {
		return nil, ErrContinuation
	}
	return json.RawMessage(raw), nil
}
