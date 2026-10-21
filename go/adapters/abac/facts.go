package abac

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// The approved native paths of the facts F1 to F8 (profile sections 8.1 and
// 8.2): each is the policy input member of section 11 written with / in
// place of a dot.
const (
	PathPrincipalID      = "/subject/principal_id"
	PathDepartment       = "/subject/department"
	PathClearance        = "/subject/clearance"
	PathDeviceCompliant  = "/environment/device/compliant"
	PathClassification   = "/resource/classification"
	PathOwningDepartment = "/resource/owning_department"
	PathNetworkZone      = "/environment/network_zone"
	PathTime             = "/environment/time"
)

// factPaths are the fact paths in the order of the facts F1 to F8.
var factPaths = []string{
	PathPrincipalID, PathDepartment, PathClearance, PathDeviceCompliant,
	PathClassification, PathOwningDepartment, PathNetworkZone, PathTime,
}

func isFactPath(path string) bool { return slices.Contains(factPaths, path) }

// ErrNoFact is what a fact source returns, wrapped or not, for a fact it does
// not hold: a document absent from the catalog, a department with no x-dept
// mapping, an address in no zone. The adapter reports it as
// [adapter.ErrUnsupportedRequirement] (profile ABAC-8). Any other error of a
// source is an outage, [adapter.ErrDependencyUnavailable].
var ErrNoFact = errors.New("abac: the source holds no value for the fact")

// SubjectSource answers the subject facts F1 to F3 of a principal: the
// principal identifier and its account state (PathPrincipalID), the
// department (PathDepartment), and the clearance (PathClearance). The claim
// carries the source's own observation and status times, never the time of
// the read (draft 8.3).
type SubjectSource interface {
	SubjectFact(ctx context.Context, realm adapter.Realm, principal, path string) (adapter.NativeClaim, error)
}

// ResourceSource answers the resource facts F5 and F6 of a resource, from the
// document catalog: PathClassification and PathOwningDepartment.
type ResourceSource interface {
	ResourceFact(ctx context.Context, realm adapter.Realm, resource, path string) (adapter.NativeClaim, error)
}

// DeviceSource answers F4, whether the device is compliant, from the
// device-management service's record of the device.
type DeviceSource interface {
	DeviceCompliance(ctx context.Context, realm adapter.Realm, deviceID string) (adapter.NativeClaim, error)
}

// EnvironmentSource answers the facts the gateway observes itself for the
// request: F7, the zone of the connection's peer address, and F8, the time.
type EnvironmentSource interface {
	NetworkZone(ctx context.Context, peer netip.Addr) (adapter.NativeClaim, error)
	Time(ctx context.Context) (adapter.NativeClaim, error)
}

// Limit is a pair of age limits in seconds (freshness profile, section 3).
type Limit struct {
	MaxAgeSeconds       int64
	StatusMaxAgeSeconds int64
}

func (l Limit) validate() error {
	if l.MaxAgeSeconds < 0 || l.StatusMaxAgeSeconds < 0 {
		return errors.New("a negative age limit")
	}
	return nil
}

func (l Limit) rule() core.FieldRule {
	return core.FieldRule{MaxAgeSeconds: l.MaxAgeSeconds, StatusMaxAgeSeconds: l.StatusMaxAgeSeconds}
}

// ProfileLimits returns the limits of profile section 8, by fact path:
// max_age 30 and status_max_age 0 for F1, F3, F5 and F6; 90 and 60 for F2;
// 300 and 30 for F4; 0 and 0 for F7 and F8.
func ProfileLimits() map[string]Limit {
	return map[string]Limit{
		PathPrincipalID:      {30, 0},
		PathDepartment:       {90, 60},
		PathClearance:        {30, 0},
		PathDeviceCompliant:  {300, 30},
		PathClassification:   {30, 0},
		PathOwningDepartment: {30, 0},
		PathNetworkZone:      {0, 0},
		PathTime:             {0, 0},
	}
}

// Zone is one entry of the zone map of trusted gateway configuration.
type Zone struct {
	Prefix netip.Prefix
	Name   string
}

// Gateway is the [EnvironmentSource] of the gateway itself: the zone of the
// longest prefix of the zone map that holds the peer address, and the
// gateway clock, each observed when it is read (profile ABAC-7, F7 and F8).
// A forwarding header never reaches it.
type Gateway struct {
	// SourceID names the gateway as the source of F7 and F8.
	SourceID string
	// Zones is the zone map.
	Zones []Zone
	// Clock is the gateway clock.
	Clock clock.Clock
}

// NetworkZone returns the zone of peer, or [ErrNoFact] when no prefix holds
// it.
func (g Gateway) NetworkZone(_ context.Context, peer netip.Addr) (adapter.NativeClaim, error) {
	peer = peer.Unmap()
	best, bits := "", -1
	for _, z := range g.Zones {
		if z.Prefix.Contains(peer) && z.Prefix.Bits() > bits {
			best, bits = z.Name, z.Prefix.Bits()
		}
	}
	if bits < 0 || best == "" {
		return adapter.NativeClaim{}, fmt.Errorf("no zone holds %s: %w", peer, ErrNoFact)
	}
	now := g.Clock.Now()
	return adapter.NativeClaim{Value: best, ObservedAt: now, StatusCheckedAt: now, SourceID: g.SourceID}, nil
}

// Time returns the gateway clock reading in Unix seconds.
func (g Gateway) Time(context.Context) (adapter.NativeClaim, error) {
	now := g.Clock.Now()
	return adapter.NativeClaim{Value: now.Unix(), ObservedAt: now, StatusCheckedAt: now, SourceID: g.SourceID}, nil
}

// factStatus is how a fact turned out, in the order of the rows of profile
// ABAC-8: the first row that matches any fact decides.
type factStatus int

const (
	factFresh       factStatus = iota
	factStale                  // row 3: FAIL with a freshness code
	factUnsupported            // row 2: missing, outside its form, no usable time
	factOutage                 // row 1: the source cannot answer
)

// reading is one fact as read for an evaluation.
type reading struct {
	path   string
	claim  adapter.NativeClaim
	status factStatus
	code   string // the freshness code of a stale fact
	err    error
}

// facts is the set of readings of one evaluation, by path.
type facts map[string]reading

// worst returns the reading of the first row of ABAC-8 that applies, and
// whether every fact is fresh.
func (f facts) worst() (reading, bool) {
	var w reading
	for _, path := range factPaths {
		if r, ok := f[path]; ok && r.status > w.status {
			w = r
		}
	}
	return w, w.status == factFresh
}

// fail returns the error of a failed set: an outage or an unsupported fact.
// A stale set is not an error of authorize_native: it is an unknown decision.
func (r reading) fail() error {
	switch r.status {
	case factOutage:
		return fmt.Errorf("abac: fact %s: %w: %w", r.path, adapter.ErrDependencyUnavailable, r.err)
	case factUnsupported:
		return fmt.Errorf("abac: fact %s: %w: %w", r.path, adapter.ErrUnsupportedRequirement, r.err)
	}
	return nil
}

// readFacts reads the facts of paths for the principal and the operation and
// evaluates each with its limits at now, with start as the evaluation start
// (freshness profile, section 3).
func (a *Adapter) readFacts(ctx context.Context, p adapter.Principal, op core.OperationContext, paths []string, start time.Time) facts {
	out := facts{}
	ev := freshness.Evaluator{Skew: clock.BaselineSkew, Start: start, Guard: a.cfg.Guard}
	for _, path := range paths {
		c, err := a.readFact(ctx, path, p, op)
		r := reading{path: path, claim: c, err: err}
		switch {
		case errors.Is(err, adapter.ErrUnsupportedRequirement), errors.Is(err, ErrNoFact):
			r.status = factUnsupported
		case err != nil:
			r.status = factOutage
		default:
			result, code := ev.Evaluate(a.limits[path].rule(), c, a.cfg.Clock.Now())
			switch {
			case result == core.CheckPass:
				if ferr := checkForm(path, c.Value, p); ferr != nil {
					r.status, r.err = factUnsupported, ferr
				}
			case code == freshness.UnsupportedRequirement:
				r.status, r.err = factUnsupported, errors.New("the source gives no usable time")
			case code == freshness.DependencyUnavailable:
				r.status, r.err = factOutage, errors.New("the guard against re-stamping is full")
			default:
				r.status, r.code = factStale, string(code)
				if ferr := checkForm(path, c.Value, p); ferr != nil {
					r.status, r.err = factUnsupported, ferr
				}
			}
		}
		out[path] = r
	}
	return out
}

// readFact reads one fact from its source. The subject facts are those of the
// principal, the resource facts those of the one resource of the operation,
// the device that of the authenticated device identifier, and the zone that of
// the authenticated peer address (profile ABAC-1, ABAC-5 to ABAC-7). Nothing
// is read from a header, the intent or an extension.
func (a *Adapter) readFact(ctx context.Context, path string, p adapter.Principal, op core.OperationContext) (adapter.NativeClaim, error) {
	switch path {
	case PathPrincipalID, PathDepartment, PathClearance:
		return a.cfg.Subjects.SubjectFact(ctx, p.Realm, p.ID, path)
	case PathClassification, PathOwningDepartment:
		res, err := oneResource(op)
		if err != nil {
			return adapter.NativeClaim{}, err
		}
		return a.cfg.Resources.ResourceFact(ctx, p.Realm, res, path)
	case PathDeviceCompliant:
		dev, ok := p.Attributes[AttrDeviceID].(string)
		if !ok || dev == "" {
			return adapter.NativeClaim{}, fmt.Errorf("no authenticated device identifier: %w", ErrNoFact)
		}
		return a.cfg.Devices.DeviceCompliance(ctx, p.Realm, dev)
	case PathNetworkZone:
		text, _ := p.Attributes[AttrPeerAddress].(string)
		peer, err := netip.ParseAddr(text)
		if err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("no authenticated peer address: %w", ErrNoFact)
		}
		return a.cfg.Environment.NetworkZone(ctx, peer)
	case PathTime:
		return a.cfg.Environment.Time(ctx)
	}
	return adapter.NativeClaim{}, fmt.Errorf("%s is not a fact path: %w", path, adapter.ErrUnsupportedRequirement)
}

// oneResource returns the one resource of the operation (profile section 2).
func oneResource(op core.OperationContext) (string, error) {
	if len(op.Resources) != 1 || op.Resources[0] == "" {
		return "", fmt.Errorf("the operation has %d resources, not one: %w", len(op.Resources), ErrNoFact)
	}
	return op.Resources[0], nil
}

// checkForm checks a fact's value against the form of profile section 11.
func checkForm(path string, v any, p adapter.Principal) error {
	switch path {
	case PathPrincipalID:
		if s, ok := v.(string); !ok || s != p.ID {
			return errors.New("the identity source names another principal")
		}
	case PathDepartment, PathOwningDepartment:
		if s, ok := v.(string); !ok || !isDepartment(s) {
			return errors.New("the department is not an x-dept identifier")
		}
	case PathClearance, PathClassification, PathNetworkZone:
		if s, ok := v.(string); !ok || s == "" {
			return errors.New("the level or zone is not a non-empty string")
		}
	case PathDeviceCompliant:
		if _, ok := v.(bool); !ok {
			return errors.New("the device compliance is not a boolean")
		}
	case PathTime:
		if _, ok := v.(int64); !ok {
			return errors.New("the time is not integer Unix seconds")
		}
	}
	return nil
}

// isDepartment reports whether s is x-dept:{hr-source-id}:{department-id} in
// the grammar of identity-mapping section 3.1: exactly two components of
// unreserved characters and percent-encodings with uppercase hexadecimal
// digits (profile ABAC-4).
func isDepartment(s string) bool {
	rest, ok := strings.CutPrefix(s, "x-dept:")
	if !ok {
		return false
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 2 {
		return false
	}
	for _, c := range parts {
		if !isComponent(c) {
			return false
		}
	}
	return true
}

func isComponent(c string) bool {
	if c == "" {
		return false
	}
	for i := 0; i < len(c); i++ {
		b := c[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '.', b == '_', b == '~':
		case b == '%' && i+2 < len(c) && isUpperHex(c[i+1]) && isUpperHex(c[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isUpperHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'A' && b <= 'F' }

// input builds the policy input of profile section 11 from the readings:
// exactly the four members, every value from its fact or from the operation.
func input(f facts, op core.OperationContext) map[string]any {
	v := func(path string) any { return f[path].claim.Value }
	return map[string]any{
		"subject": map[string]any{
			"principal_id": v(PathPrincipalID),
			"department":   v(PathDepartment),
			"clearance":    v(PathClearance),
		},
		"resource": map[string]any{
			"id":                op.Resources[0],
			"classification":    v(PathClassification),
			"owning_department": v(PathOwningDepartment),
		},
		"action": map[string]any{"id": op.Action},
		"environment": map[string]any{
			"device":       map[string]any{"compliant": v(PathDeviceCompliant)},
			"network_zone": v(PathNetworkZone),
			"time":         v(PathTime),
		},
	}
}
