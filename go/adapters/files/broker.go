package files

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
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
	Protocol        = "http"
	Version         = "1.1"
	MappingRevision = "pact-files-1"
)

// Mechanism is the Mechanism of a principal the broker authenticates.
const Mechanism adapter.Mechanism = "negotiate"

// ActionRead is the action of route R1.
const ActionRead = "file.read"

// The approved native paths the broker answers from the access token of the
// completed exchange (profile section 3, read_native_claim).
const (
	PathPrincipalID = "/attributes/environment/principal_id"
	PathGroupIDs    = "/attributes/environment/group_ids"
)

// CheckExecutionIdentity is the installed check the broker runs itself
// (draft 17.5, profile TA-3, TA-4).
const CheckExecutionIdentity = "execution-identity-v1"

// The profile parameters of the reference configuration (profile section 1),
// illustrative policy choices.
const (
	DefaultContextMaxAge     = 300 * time.Second
	DefaultHandleMaxLifetime = 300 * time.Second
)

// The sources the broker names.
const (
	// DefaultOpenSourceID names the native open as the source of a decision.
	DefaultOpenSourceID = "files-native-open"
	// RegistrySourceID names the file registry as the source of the denial
	// of a resource it does not hold.
	RegistrySourceID = "files-registry"
	// ContextSourceID names the security context of the completed exchange
	// as the source of a claim (profile F2).
	ContextSourceID = "windows-security-context"
	// ImpersonationSourceID names the impersonation of the broker thread as
	// the source of execution-identity-v1.
	ImpersonationSourceID = "files-impersonation"
)

const (
	maxBody               = 8 << 20
	headerNormalizationID = "pact-files-header-normalization-1"
	guardCapacity         = 4096
)

// Errors of the broker. Each wraps the sentinel of package adapter for its
// draft 13.4 code.
var (
	// ErrImpersonationUnavailable: the principal's security context cannot be
	// impersonated, so nothing is opened (profile TA-3).
	ErrImpersonationUnavailable = fmt.Errorf("files: the principal cannot be impersonated: %w", adapter.ErrDependencyUnavailable)
	// ErrExecutorMismatch: the thread's effective identity is not the
	// principal, so nothing is opened (profile TA-4).
	ErrExecutorMismatch = fmt.Errorf("files: the effective identity is not the principal: %w", adapter.ErrContextMismatch)
	// ErrUnhealthy: a revert failed, and the broker refuses every protected
	// operation (profile TA-6).
	ErrUnhealthy = fmt.Errorf("files: the broker is unhealthy after a failed revert: %w", adapter.ErrDependencyUnavailable)
	// ErrObjectMismatch: the opened object is not the registered one
	// (profile PB-4).
	ErrObjectMismatch = fmt.Errorf("files: the opened object is not the registered object: %w", adapter.ErrContextMismatch)
	// ErrHandleExpired: the handle outlived handle_max_lifetime_seconds
	// (profile HI-2).
	ErrHandleExpired = fmt.Errorf("files: the handle is older than its lifetime: %w", adapter.ErrDependencyUnavailable)
)

// Config configures a Broker.
type Config struct {
	// Realm is the PACT realm the broker serves.
	Realm adapter.Realm
	// Origin and HeaderAllowlist are the baseline HTTP mapping's trusted
	// configuration (draft 10.2).
	Origin          string
	HeaderAllowlist []string
	// Mappings are installed mapping revisions besides pact-files-1, whose
	// routes are [Routes] and cannot be replaced.
	Mappings map[string][]installed.Route
	// Actions gives each action the access right the open requests; nil is
	// file.read with [AccessRead]. An operation whose action has none is a
	// context mismatch.
	Actions map[string]Access

	// Package, Impersonator and FileSystem are the native seams.
	Package      SecurityPackage
	Impersonator Impersonator
	FileSystem   FileSystem
	// Files is the file registry.
	Files Registry
	// Contexts holds the completed contexts by principal; nil is a store in
	// memory.
	Contexts ContextStore

	// Registry is the enrollment registry.
	Registry enroll.Registry
	// Claims are the deployment's sources of other approved paths.
	Claims map[string]installed.ClaimSource
	// Checks are the deployment's installed checks besides
	// execution-identity-v1.
	Checks map[string]installed.InstalledCheck
	Guard  *freshness.Monotonic
	// Reporting signs outcome reports.
	Reporting *installed.Reporting
	// ExecutionVisible says that the broker observes executions; it does
	// when it serves reads with [Broker.Execute].
	ExecutionVisible bool

	// OpenSourceID names the native open in decisions; empty is
	// DefaultOpenSourceID.
	OpenSourceID string
	// ContextMaxAge and HandleMaxLifetime are the profile parameters; zero is
	// the default.
	ContextMaxAge     time.Duration
	HandleMaxLifetime time.Duration
	// OnUnhealthy, when set, is told once that the broker became unhealthy,
	// so that its supervisor terminates it (profile TA-6).
	OnUnhealthy func(error)

	// Clock is the broker's only source of the current time.
	Clock clock.Clock
}

// Routes returns the routes of mapping revision pact-files-1: route R1 of
// profile section 2.
func Routes() []installed.Route {
	return []installed.Route{{Method: http.MethodGet, Path: "/files/{file_id}/content", Action: ActionRead, Resource: "file:{file_id}"}}
}

// Broker is the file broker adapter.
type Broker struct {
	cfg      Config
	mappings map[string][]installed.Route
	actions  map[string]Access
	contexts ContextStore

	mu        sync.Mutex
	unhealthy error
	handles   map[HandleKey]*handleRecord
}

var _ adapter.Adapter = (*Broker)(nil)

// New returns a broker over cfg.
func New(cfg Config) (*Broker, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("files: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("files: the realm needs a tenant and an environment")
	case cfg.Package == nil || cfg.Impersonator == nil || cfg.FileSystem == nil:
		return nil, errors.New("files: the security package, the impersonator and the file system are required")
	case cfg.Files == nil:
		return nil, errors.New("files: no file registry")
	case cfg.Registry == nil:
		return nil, errors.New("files: no enrollment registry")
	case cfg.ContextMaxAge < 0 || cfg.HandleMaxLifetime < 0:
		return nil, errors.New("files: negative context age or handle lifetime")
	}
	if cfg.ContextMaxAge == 0 {
		cfg.ContextMaxAge = DefaultContextMaxAge
	}
	if cfg.HandleMaxLifetime == 0 {
		cfg.HandleMaxLifetime = DefaultHandleMaxLifetime
	}
	if cfg.OpenSourceID == "" {
		cfg.OpenSourceID = DefaultOpenSourceID
	}
	for _, p := range []string{PathPrincipalID, PathGroupIDs} {
		if _, ok := cfg.Claims[p]; ok {
			return nil, fmt.Errorf("files: %s is answered from the access token", p)
		}
	}
	for p, src := range cfg.Claims {
		if src == nil {
			return nil, fmt.Errorf("files: no source for %s", p)
		}
	}
	if _, ok := cfg.Checks[CheckExecutionIdentity]; ok {
		return nil, fmt.Errorf("files: %s is the broker's own check", CheckExecutionIdentity)
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("files: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("files: %w", err)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	b := &Broker{cfg: cfg, contexts: cfg.Contexts, handles: map[HandleKey]*handleRecord{},
		mappings: map[string][]installed.Route{MappingRevision: Routes()}, actions: cfg.Actions}
	if b.contexts == nil {
		b.contexts = NewContextStore(cfg.ContextMaxAge)
	}
	if b.actions == nil {
		b.actions = map[string]Access{ActionRead: AccessRead}
	}
	for version, routes := range cfg.Mappings {
		if version == MappingRevision {
			return nil, fmt.Errorf("files: mapping %s is fixed by the profile", MappingRevision)
		}
		b.mappings[version] = routes
	}
	for version, routes := range b.mappings {
		if err := b.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("files: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("files: mapping %q: %w", version, err)
			}
		}
	}
	return b, nil
}

// Describe returns the adapter descriptor.
func (b *Broker) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

func (b *Broker) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                b.cfg.Origin,
		HeaderAllowlist:       b.cfg.HeaderAllowlist,
		HeaderNormalizationID: headerNormalizationID,
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// MarkUnhealthy records that the process can no longer be trusted to run a
// protected operation, as after a failed revert: every later protected
// operation is refused with no open and no bytes (profile TA-6). The first
// mark is reported to Config.OnUnhealthy.
func (b *Broker) MarkUnhealthy(err error) {
	if err == nil {
		err = errors.New("marked unhealthy")
	}
	b.mu.Lock()
	first := b.unhealthy == nil
	if first {
		b.unhealthy = err
	}
	b.mu.Unlock()
	if first && b.cfg.OnUnhealthy != nil {
		b.cfg.OnUnhealthy(err)
	}
}

// Healthy returns nil, or an error that wraps [ErrUnhealthy] once the broker
// was marked unhealthy.
func (b *Broker) Healthy() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unhealthy != nil {
		return fmt.Errorf("%w (%v)", ErrUnhealthy, b.unhealthy)
	}
	return nil
}

// Close closes every open handle and the tokens of the default context
// store.
func (b *Broker) Close() error {
	b.mu.Lock()
	hs := b.handles
	b.handles = map[HandleKey]*handleRecord{}
	b.mu.Unlock()
	for _, h := range hs {
		_ = h.h.Close()
	}
	if s, ok := b.contexts.(*memoryContexts); ok {
		s.close()
	}
	return nil
}

func live(ctx context.Context, fn string) error {
	if err := installed.Live(ctx); err != nil {
		return fmt.Errorf("files: %s: %w", fn, err)
	}
	return nil
}

// Context is a completed Negotiate context: its access token and the instant
// the final call of the exchange returned.
type Context struct {
	Token       Token
	CompletedAt time.Time
}

// ContextStore holds the completed context of each principal the broker
// authenticated, by realm and principal identifier.
type ContextStore interface {
	Put(realm adapter.Realm, principalID string, c Context)
	Get(realm adapter.Realm, principalID string) (Context, bool)
}

// NewContextStore returns a ContextStore in memory that keeps a context
// until it is older than retain. A replaced or dropped token is closed only
// once it is older than twice retain, so that no request that read it while
// it was current still uses it.
func NewContextStore(retain time.Duration) ContextStore {
	if retain <= 0 {
		retain = DefaultContextMaxAge
	}
	return &memoryContexts{m: map[contextKey]Context{}, retain: retain}
}

type contextKey struct {
	realm adapter.Realm
	id    string
}

type memoryContexts struct {
	mu      sync.Mutex
	retain  time.Duration
	m       map[contextKey]Context
	retired []Context
}

func (s *memoryContexts) Put(realm adapter.Realm, id string, c Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := contextKey{realm, id}
	if old, ok := s.m[k]; ok && old.Token != c.Token {
		s.retired = append(s.retired, Context{Token: old.Token, CompletedAt: c.CompletedAt})
	}
	s.m[k] = c
	for k, old := range s.m {
		if c.CompletedAt.Sub(old.CompletedAt) > s.retain {
			delete(s.m, k)
			s.retired = append(s.retired, Context{Token: old.Token, CompletedAt: c.CompletedAt})
		}
	}
	kept := s.retired[:0]
	for _, r := range s.retired {
		if c.CompletedAt.Sub(r.CompletedAt) > 2*s.retain {
			_ = r.Token.Close()
			continue
		}
		kept = append(kept, r)
	}
	s.retired = kept
}

func (s *memoryContexts) Get(realm adapter.Realm, id string) (Context, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[contextKey{realm, id}]
	return c, ok
}

func (s *memoryContexts) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.m {
		_ = c.Token.Close()
	}
	for _, r := range s.retired {
		_ = r.Token.Close()
	}
	s.m, s.retired = map[contextKey]Context{}, nil
}

// context returns the principal's completed context when it is not older
// than the context age (profile IA-9).
func (b *Broker) context(realm adapter.Realm, id string) (Context, bool) {
	c, ok := b.contexts.Get(realm, id)
	if !ok || c.Token == nil {
		return Context{}, false
	}
	if b.cfg.Clock.Now().Sub(c.CompletedAt) > b.cfg.ContextMaxAge {
		return Context{}, false
	}
	return c, true
}
