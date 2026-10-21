package adapter

import (
	"context"
	"net/http"
	"slices"
	"time"
)

// Realm is the trust realm a principal and a binding belong to: one tenant in
// one environment.
type Realm struct {
	TenantID      string
	EnvironmentID string
}

// Workload is the namespaced identifier of the authenticated workload, such as
// a native client, service account, certificate subject or local process
// identity. It is opaque to PACT and compared for exact equality.
type Workload string

// Mechanism names how the native system authenticated the request, for example
// a mutual-TLS client certificate or a bearer token. The set is open; PACT
// records the value and does not interpret it.
type Mechanism string

// Principal is the authenticated principal and workload context that
// AuthenticateNative produces. It comes only from the native system's
// authenticated context, never from the request's own claims (draft 8.5).
type Principal struct {
	// ID identifies the principal. It is namespaced by issuer and tenant so
	// that two same-spelled identities of different issuers never compare
	// equal.
	ID string
	// Realm is the tenant and environment the principal authenticated in.
	Realm Realm
	// Workload is the authenticated workload the request came from.
	Workload Workload
	// Mechanism is how the principal authenticated.
	Mechanism Mechanism
	// AuthenticatedAt is when native authentication of this request completed.
	AuthenticatedAt time.Time
	// Attributes holds further authenticated attributes the native system
	// supplied, such as groups. Each value is a JSON-compatible Go value.
	Attributes map[string]any
}

// DenialReason is the public reason of a [NativeDenial]. The set is closed and
// each value is something the caller already knows about its own request, so a
// denial never discloses whether an account, a tenant or an issuer exists
// (draft 13.4).
type DenialReason string

const (
	// DenialNoCredential: the request carried no credential.
	DenialNoCredential DenialReason = "NO_CREDENTIAL"
	// DenialCredentialRejected: a credential was presented and not accepted,
	// whether it was malformed, expired, revoked, unknown or unverifiable.
	DenialCredentialRejected DenialReason = "CREDENTIAL_REJECTED"
)

var denialReasonValues = []DenialReason{DenialNoCredential, DenialCredentialRejected}

// Valid reports whether r is a defined value.
func (r DenialReason) Valid() bool { return slices.Contains(denialReasonValues, r) }

// NativeDenial is the error AuthenticateNative returns when the native system
// evaluated the request and did not authenticate it. It is returned as
// *NativeDenial, so a caller matches it with errors.As or with
// errors.Is(err, [ErrInvalidProof]). It carries no cause: an adapter logs
// internal detail itself.
type NativeDenial struct {
	// Reason is the public reason. A value outside the defined set is reported
	// as [DenialCredentialRejected].
	Reason DenialReason
}

// PublicReason returns Reason when it is a defined value and
// [DenialCredentialRejected] otherwise, so that free text an adapter puts in
// Reason is never shown.
func (d *NativeDenial) PublicReason() DenialReason {
	if d != nil && d.Reason.Valid() {
		return d.Reason
	}
	return DenialCredentialRejected
}

// Error returns a message built from the public reason only.
func (d *NativeDenial) Error() string {
	return "adapter: native authentication denied: " + string(d.PublicReason())
}

// Code returns [CodeInvalidProof].
func (d *NativeDenial) Code() Code { return CodeInvalidProof }

// Is reports whether target is [ErrInvalidProof].
func (d *NativeDenial) Is(target error) bool { return target == ErrInvalidProof }

// NativeAuthenticator is the draft 17.1 function authenticate_native.
type NativeAuthenticator interface {
	// AuthenticateNative authenticates the actual request with the
	// environment's existing identity system and returns the principal and
	// workload context.
	//
	// It returns a *[NativeDenial] when authentication was evaluated and
	// failed. It returns an error that wraps [ErrDependencyUnavailable] when
	// it could not be evaluated. It never returns a zero Principal with a nil
	// error.
	AuthenticateNative(ctx context.Context, r *http.Request) (Principal, error)
}
