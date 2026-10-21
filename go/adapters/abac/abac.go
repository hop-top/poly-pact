package abac

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// The descriptor of the adapter (profile section 1).
const (
	Protocol        = "opa-data-api"
	Version         = "v1"
	MappingRevision = "pact-abac-1"
)

// The Principal attributes that authenticate_native sets and this profile
// reads (profile ABAC-6, ABAC-7; the adapters README, "call").
const (
	// AttrDeviceID is the identifier of the device whose credential native
	// authentication validated.
	AttrDeviceID = "device_id"
	// AttrPeerAddress is the transport-level peer address of the connection,
	// as text.
	AttrPeerAddress = "peer_address"
)

// maxBody is the largest request body the adapter reads to digest it.
const maxBody = 8 << 20

// headerNormalizationID names the header normalization of the baseline HTTP
// mapping, which package binding applies.
const headerNormalizationID = "pact-abac-header-normalization-1"

// guardCapacity bounds the guard against re-stamping that New creates when
// the configuration supplies none.
const guardCapacity = 4096

// Config names the gateway's native systems and its trusted configuration.
// Every value comes from gateway configuration, never from a request.
type Config struct {
	// Realm is the tenant and environment of the gateway.
	Realm adapter.Realm
	// Origin is the public HTTPS origin of the gateway, the only source of the
	// scheme, host and port of a target URI (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [DocumentRoutes] under [MappingRevision].
	Mappings map[string][]Route

	// Authenticator is the native authentication of the mechanism that
	// authenticated the request, which the profile inherits (profile
	// section 7). It sets the Principal attributes [AttrDeviceID] and
	// [AttrPeerAddress]. Required.
	Authenticator adapter.NativeAuthenticator
	// Bindings resolves agent bindings, as the authenticating mechanism's
	// profile does. Required.
	Bindings adapter.BindingResolver

	// Subjects, Resources and Devices are the authoritative fact sources of
	// profile section 8; Environment is the gateway's own observation of the
	// network zone and the time. Required.
	Subjects    SubjectSource
	Resources   ResourceSource
	Devices     DeviceSource
	Environment EnvironmentSource
	// Limits are the age limits of each fact path. Nil uses
	// [ProfileLimits]; a deployment may tighten a limit and may not loosen
	// one (profile section 8).
	Limits map[string]Limit
	// Guard is the guard against re-stamping that the facts and the installed
	// checks share (freshness profile, section 7). Nil creates an empty one.
	Guard *freshness.Monotonic

	// PDP is the policy decision point.
	PDP PDP
	// Entry is the installed ABAC check entry of profile ABAC-16, which
	// [Adapter.CheckContext] and [Gate] use. Optional for the seven functions.
	Entry *Entry

	// Claims are the sources of approved native paths other than the fact
	// paths of this profile, by path.
	Claims map[string]ClaimSource
	// Checks are the installed context checks by exact check id, run by
	// CheckContext.
	Checks map[string]InstalledCheck

	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations it forwards. The executor reports executions under this
	// profile (ABAC-30), so it is false there.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// Route maps a method and a path template to an action and a resource
// template (package installed).
type Route = installed.Route

// ClaimSource is the source of an approved native path other than the fact
// paths.
type ClaimSource = installed.ClaimSource

// ClaimRecord is one value of a [ClaimSource].
type ClaimRecord = installed.ClaimRecord

// InstalledCheck is a context check as the gateway installed it.
type InstalledCheck = installed.InstalledCheck

// Check is the native implementation of an installed context check.
type Check = installed.Check

// CheckRecord is what a [Check] found.
type CheckRecord = installed.CheckRecord

// Freshness is a pair of age limits in seconds of an installed check.
type Freshness = installed.Freshness

// Reporting is the signer of outcome reports.
type Reporting = installed.Reporting

// DocumentRoutes is the route table of mapping revision pact-abac-1: route R1
// of the profile, GET /api/documents/{document_id}, the action document.read
// on the resource document:{document_id} (profile section 2).
func DocumentRoutes() []Route {
	return []Route{{Method: http.MethodGet, Path: "/api/documents/{document_id}", Action: "document.read", Resource: "document:{document_id}"}}
}

// Adapter is the ABAC adapter. It is safe for concurrent use when its native
// systems are.
type Adapter struct {
	cfg      Config
	mappings map[string][]Route
	limits   map[string]Limit
	pdp      *pdpClient
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("abac: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("abac: the gateway realm needs a tenant and an environment")
	case cfg.Authenticator == nil || cfg.Bindings == nil:
		return nil, errors.New("abac: the inherited authentication and binding resolution are required")
	case cfg.Subjects == nil || cfg.Resources == nil || cfg.Devices == nil || cfg.Environment == nil:
		return nil, errors.New("abac: a fact source is missing")
	}
	limits := cfg.Limits
	if limits == nil {
		limits = ProfileLimits()
	}
	for _, path := range factPaths {
		l, ok := limits[path]
		if !ok {
			return nil, fmt.Errorf("abac: no age limits for %s", path)
		}
		if err := l.validate(); err != nil {
			return nil, fmt.Errorf("abac: %s: %w", path, err)
		}
		if p, ok := ProfileLimits()[path]; ok && (l.MaxAgeSeconds > p.MaxAgeSeconds || l.StatusMaxAgeSeconds > p.StatusMaxAgeSeconds) {
			return nil, fmt.Errorf("abac: the limits of %s are looser than those of the profile", path)
		}
	}
	client, err := newPDPClient(cfg.PDP)
	if err != nil {
		return nil, fmt.Errorf("abac: %w", err)
	}
	for path, src := range cfg.Claims {
		if isFactPath(path) {
			return nil, fmt.Errorf("abac: %s is answered by the fact sources", path)
		}
		if src == nil {
			return nil, fmt.Errorf("abac: no source for %s", path)
		}
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("abac: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("abac: %w", err)
	}
	if err := cfg.Entry.validate(); err != nil {
		return nil, fmt.Errorf("abac: %w", err)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings, limits: limits, pdp: client}
	if a.mappings == nil {
		a.mappings = map[string][]Route{MappingRevision: DocumentRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("abac: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("abac: mapping %q: %w", version, err)
			}
		}
	}
	return a, nil
}

// Describe returns the descriptor of the profile: opa-data-api, v1,
// pact-abac-1.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

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
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("abac: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}
