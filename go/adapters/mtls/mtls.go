package mtls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// The descriptor of the adapter (profile section 1).
const (
	Protocol        = "mtls"
	Version         = "1.3"
	MappingRevision = "pact-mtls-1"
)

// Mechanism is the Mechanism of a principal the adapter authenticates.
const Mechanism adapter.Mechanism = "mtls"

// PathWorkloadID is the native path the profile claims (MTLS-30).
const PathWorkloadID = "/attributes/environment/workload_id"

// The attributes of an authenticated principal.
const (
	// AttrConfirmation is the attribute that holds the thumbprint of the peer
	// leaf's public key as {"jkt": <thumbprint>} (MTLS-9).
	AttrConfirmation = "cnf"
	// AttrStatus is the attribute that holds the times of the identity:
	// {"status_time": <Unix seconds>} and, on a direct listener,
	// "observed_at", the instant of the first evaluation of the connection
	// (MTLS-30).
	AttrStatus = "mtls"
)

// Role is the role of a listener (MTLS-22).
type Role string

const (
	// RoleDirect is a listener whose TLS peer is the agent's own workload.
	RoleDirect Role = "direct"
	// RoleTerminated is a listener whose TLS peer is an allowlisted
	// terminator that relays the requests of end clients.
	RoleTerminated Role = "terminated"
)

// SANKind is the kind of subject alternative name a pinned CA uses to name
// workloads.
type SANKind string

const (
	SANKindURI SANKind = "uri"
	SANKindDNS SANKind = "dns"
)

// CAEntry is an entry of the pinned CA set (MTLS-2).
type CAEntry struct {
	// CAID is the configured identifier of the authority, never the text of
	// its subject name.
	CAID string
	// Certificate is the CA certificate, the trust anchor.
	Certificate *x509.Certificate
	// SANKind is the kind of name the authority uses for workloads.
	SANKind SANKind
}

// DefaultStatusBound is the status bound S of the profile's reference
// configuration (MTLS-14), an illustrative policy choice.
const DefaultStatusBound = 360 * time.Second

// DefaultMaxCRLBytes is the size limit of a revocation list (MTLS-12 (g))
// when the configuration sets none.
const DefaultMaxCRLBytes = 1 << 20

// maxBody is the largest request body the adapter reads to digest it.
const maxBody = 8 << 20

// headerNormalizationID names the header normalization of the baseline HTTP
// mapping, which package binding applies.
const headerNormalizationID = "pact-mtls-header-normalization-1"

// guardCapacity bounds the guard against re-stamping that New creates when
// the configuration supplies none.
const guardCapacity = 4096

// Config names the listener's trusted configuration and the gateway's native
// systems. Every value comes from gateway configuration, never from a request.
type Config struct {
	// Role is the role of the listener. Required.
	Role Role
	// Realm is the tenant and environment of the listener (MTLS-6).
	Realm adapter.Realm
	// PinnedCAs is the pinned CA set. Required.
	PinnedCAs []CAEntry
	// Terminators is the terminator allowlist of a terminated listener, as
	// identifiers of MTLS-6 (MTLS-23).
	Terminators []adapter.Workload
	// StatusBound is the status bound S (MTLS-14). Zero is
	// [DefaultStatusBound].
	StatusBound time.Duration
	// MaxCRLBytes is the size limit of a revocation list. Zero is
	// [DefaultMaxCRLBytes].
	MaxCRLBytes int
	// ForwardedIdentityHeaders names further headers of the deployment that
	// carry data from a client certificate; they are removed with the
	// headers of MTLS-26.
	ForwardedIdentityHeaders []string

	// Origin is the public HTTPS origin of the gateway, the only source of the
	// scheme, host and port of a target URI (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [ReconciliationRoutes] under [MappingRevision].
	Mappings map[string][]installed.Route

	// Registry is the enrollment registry. Required.
	Registry enroll.Registry
	// Claims are the sources of approved native paths other than
	// [PathWorkloadID], by path.
	Claims map[string]installed.ClaimSource
	// Checks are the context checks the deployment installs, by exact id.
	Checks map[string]installed.InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share. Nil creates an empty one.
	Guard *freshness.Monotonic
	// Permissions is the native permission lookup. Required.
	Permissions installed.PermissionLookup
	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *installed.Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations it forwards.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// ReconciliationRoutes is the route table of mapping revision pact-mtls-1:
// route R1 of the profile, GET /api/v1/reconciliation/records/{record_id},
// the action reconciliation.record.read on reconciliation-record:{record_id}.
func ReconciliationRoutes() []installed.Route {
	return []installed.Route{{
		Method: http.MethodGet, Path: "/api/v1/reconciliation/records/{record_id}",
		Action: "reconciliation.record.read", Resource: "reconciliation-record:{record_id}",
	}}
}

// Adapter is the mTLS adapter of one listener. It is safe for concurrent use
// when its native systems are.
type Adapter struct {
	cfg      Config
	mappings map[string][]installed.Route
	pinned   atomic.Pointer[pinnedSet]

	mu        sync.Mutex
	snapshots map[string]*snapshot
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("mtls: no clock")
	case cfg.Role != RoleDirect && cfg.Role != RoleTerminated:
		return nil, fmt.Errorf("mtls: listener role %q is not direct or terminated", cfg.Role)
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("mtls: the listener realm needs a tenant and an environment")
	case cfg.Registry == nil:
		return nil, errors.New("mtls: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("mtls: no permission lookup")
	case cfg.StatusBound < 0 || cfg.MaxCRLBytes < 0:
		return nil, errors.New("mtls: negative status bound or list size")
	case cfg.Role == RoleDirect && len(cfg.Terminators) > 0:
		return nil, errors.New("mtls: a direct listener has no terminators (MTLS-22)")
	}
	if cfg.StatusBound == 0 {
		cfg.StatusBound = DefaultStatusBound
	}
	if cfg.MaxCRLBytes == 0 {
		cfg.MaxCRLBytes = DefaultMaxCRLBytes
	}
	for path, src := range cfg.Claims {
		if path == PathWorkloadID {
			return nil, fmt.Errorf("mtls: %s is answered from the TLS state", path)
		}
		if src == nil {
			return nil, fmt.Errorf("mtls: no source for %s", path)
		}
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("mtls: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("mtls: %w", err)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	cfg.Terminators = slices.Clone(cfg.Terminators)
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings, snapshots: map[string]*snapshot{}}
	if a.mappings == nil {
		a.mappings = map[string][]installed.Route{MappingRevision: ReconciliationRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("mtls: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("mtls: mapping %q: %w", version, err)
			}
		}
	}
	if err := a.ReplacePinnedCAs(cfg.PinnedCAs); err != nil {
		return nil, err
	}
	return a, nil
}

// Describe returns the descriptor of the profile: mtls, 1.3, pact-mtls-1.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

// Role returns the role of the listener.
func (a *Adapter) Role() Role { return a.cfg.Role }

// bindingConfig is the baseline HTTP mapping under one installed revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: headerNormalizationID,
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := installed.Live(ctx); err != nil {
		return fmt.Errorf("mtls: %s: %w", fn, err)
	}
	return nil
}
