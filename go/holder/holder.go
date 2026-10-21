package holder

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
)

// Holder is the agent side of one gateway: the enrolled agent, its key, the
// gateway it presents to and the requirement publishers it trusts.
type Holder struct {
	// AgentID is the agent's agent_id (draft 6.1): the sub of its
	// contracts and the iss and sub of its presentations.
	AgentID string
	// Keys holds the enrolled holder key.
	Keys KeySource
	// Gateway is the gateway's identifier: the aud of contracts and
	// presentations, and the gateway_id of its metadata.
	Gateway string
	// Realm is the gateway's tenant and environment.
	Realm adapter.Realm
	// Publishers maps the iss of each requirement publisher the holder
	// trusts for this gateway to its keys (draft 7.3). They come from
	// configuration, never from discovery (draft 13.1).
	Publishers map[string]*jws.KeySet
	// Algorithms are the negotiated JWS algorithms; nil is ES256 alone.
	Algorithms jws.Algorithms
	// Extensions lists the contract extensions the holder supports; a
	// contract with any other defers (draft 7.1, 21).
	Extensions []string
	// Skew is the allowed clock skew, 0 to 5 s (draft 7.5).
	Skew time.Duration
	// Lifetime is a presentation's exp - iat, whole seconds from 1 s to
	// 60 s; zero is 60 s (draft 7.5, 20.1).
	Lifetime time.Duration
	// Random is the source of presentation jti values; nil is crypto/rand.
	Random io.Reader
	// Transport is the transport profile the holder sends its presentations
	// over: contract.TransportHTTPS, the default when empty, or
	// contract.TransportStdioIPC (draft 13.3.1).
	Transport string
}

// holderKey is the key source's public key, checked, with its algorithm
// and RFC 7638 thumbprint.
type holderKey struct {
	jwk jws.JWK
	alg string
	jkt core.Digest
}

// check validates the holder's configuration and returns the presentation
// lifetime in seconds.
func (h *Holder) check() (int64, error) {
	switch {
	case h.AgentID == "" || h.Gateway == "" || h.Realm.TenantID == "" || h.Realm.EnvironmentID == "":
		return 0, fmt.Errorf("%w: AgentID, Gateway and Realm are required", ErrInvalidMessage)
	case h.Keys == nil:
		return 0, fmt.Errorf("%w: no key source", ErrInvalidMessage)
	case h.Skew < 0 || h.Skew > clock.BaselineSkew:
		return 0, fmt.Errorf("%w: skew %v outside 0 to %v", ErrInvalidMessage, h.Skew, clock.BaselineSkew)
	}
	lifetime := h.Lifetime
	if lifetime == 0 {
		lifetime = 60 * time.Second
	}
	if lifetime < time.Second || lifetime > 60*time.Second || lifetime%time.Second != 0 {
		return 0, fmt.Errorf("%w: presentation lifetime %v is not 1 to 60 whole seconds", ErrInvalidMessage, h.Lifetime)
	}
	return int64(lifetime / time.Second), nil
}

// key returns the key source's public key. A key that is not a valid public
// key of an implemented algorithm is invalid; one whose algorithm is not
// negotiated is unsupported.
func (h *Holder) key(ctx context.Context) (holderKey, error) {
	jwk, err := h.Keys.PublicJWK(ctx)
	if err != nil {
		return holderKey{}, fmt.Errorf("%w: key source: %v", ErrDependencyUnavailable, err)
	}
	// Only the members that identify the key are embedded (RFC 7638
	// section 3.2); kid, alg and use play no part in a holder key's
	// selection (draft 7.2).
	jwk = jws.JWK{Kty: jwk.Kty, Crv: jwk.Crv, X: jwk.X, Y: jwk.Y}
	alg, err := jwk.Algorithm()
	if err != nil {
		return holderKey{}, fmt.Errorf("%w: key source key: %v", ErrInvalidProof, err)
	}
	if !h.Algorithms.Accepts(alg) {
		return holderKey{}, fmt.Errorf("%w: algorithm %s is not negotiated", ErrUnsupportedRequirement, alg)
	}
	jkt, err := jws.Thumbprint(jwk)
	if err != nil {
		return holderKey{}, fmt.Errorf("%w: key source key: %v", ErrInvalidProof, err)
	}
	return holderKey{jwk: jwk, alg: alg, jkt: jkt}, nil
}

// Negotiate checks the gateway metadata md (draft 13.1) and returns the wire
// version to use: the gateway is h.Gateway in h.Realm's environment
// (ErrContextMismatch), it lists wire version 0.1, the only one this holder
// implements, compared exactly (ErrUnsupportedVersion; the holder never
// downgrades, draft 21), and it lists the algorithm of the holder key, which
// h.Algorithms also accepts (ErrUnsupportedRequirement). The metadata
// establishes no trust: publisher keys come from h.Publishers only.
func (h *Holder) Negotiate(ctx context.Context, md core.GatewayMetadata) (string, error) {
	if _, err := h.check(); err != nil {
		return "", err
	}
	if md.GatewayID != h.Gateway || md.EnvironmentID != h.Realm.EnvironmentID {
		return "", fmt.Errorf("%w: metadata of gateway %q in %q", ErrContextMismatch, md.GatewayID, md.EnvironmentID)
	}
	if !slices.Contains(md.WireVersions, core.Version) {
		return "", fmt.Errorf("%w: gateway wire versions %q, holder %q", ErrUnsupportedVersion, md.WireVersions, core.Version)
	}
	k, err := h.key(ctx)
	if err != nil {
		return "", err
	}
	if !slices.Contains(md.JWSAlgorithms, core.JWSAlgorithm(k.alg)) {
		return "", fmt.Errorf("%w: gateway does not list %s", ErrUnsupportedRequirement, k.alg)
	}
	return core.Version, nil
}

// VerifyContract verifies a received requirement contract for the intent
// and operation the agent is about to perform, at the holder time now:
//
//  1. the publisher's signature under the keys h.Publishers holds for its
//     iss, the typ, the schema and the time rules of draft 7.5 with the
//     60-second lifetime ([contract.Verifier.Verify]): ErrInvalidProof,
//     ErrInvalidMessage, ErrUnsupportedVersion for a pact_version other
//     than 0.1, or ErrExpired at or after exp;
//  2. sub, aud and realm are h.AgentID, h.Gateway and h.Realm
//     (ErrContextMismatch), every extension is one of h.Extensions
//     (ErrUnsupportedRequirement, which defers: draft 7.1, 21), and an
//     enforced-mode contract names h.Transport ([contract.Contract.Transport];
//     ErrContextMismatch, the downgrade rule of draft 13.3.1);
//  3. holder_jkt is the thumbprint of the key source's key
//     (ErrInvalidProof, draft 6.2);
//  4. intent_digest and operation_digest are the object_digest of intent
//     and op (ErrContextMismatch): a contract for another intent or
//     operation, or for one that changed since, does not apply (draft
//     10.3).
//
// It does not check whether the contract is still active at the gateway or
// consume its nonce; the validator does.
func (h *Holder) VerifyContract(ctx context.Context, compact string, intent core.Intent, op core.OperationContext, now time.Time) (contract.Contract, error) {
	if _, err := h.check(); err != nil {
		return contract.Contract{}, err
	}
	k, err := h.key(ctx)
	if err != nil {
		return contract.Contract{}, err
	}
	return h.verifyContract(compact, intent, op, k, now)
}

func (h *Holder) verifyContract(compact string, intent core.Intent, op core.OperationContext, k holderKey, now time.Time) (contract.Contract, error) {
	if err := checkInputLimits(intent, op); err != nil {
		return contract.Contract{}, err
	}
	if err := checkVersion(compact); err != nil {
		return contract.Contract{}, err
	}
	v := contract.Verifier{Publishers: h.Publishers, Algorithms: h.Algorithms, Skew: h.Skew}
	c, err := v.Verify(compact, now)
	if err != nil {
		return contract.Contract{}, translate(err)
	}
	if err := c.Check(contract.Expect{AgentID: h.AgentID, Audience: h.Gateway, Realm: h.Realm, SupportedExtensions: h.Extensions}); err != nil {
		return contract.Contract{}, translate(err)
	}
	if named := c.Transport(); c.Claims.Mode == core.ModeEnforced && named != h.transport() {
		return contract.Contract{}, fmt.Errorf("%w: contract names transport %q, holder sends over %q", ErrContextMismatch, named, h.transport())
	}
	if c.Claims.HolderJKT != k.jkt {
		return contract.Contract{}, fmt.Errorf("%w: contract holder_jkt %s, key source %s", ErrInvalidProof, c.Claims.HolderJKT, k.jkt)
	}
	intentDigest, err := digest.ObjectDigest(intent)
	if err != nil {
		return contract.Contract{}, fmt.Errorf("%w: intent: %v", ErrInvalidMessage, err)
	}
	opDigest, err := digest.ObjectDigest(op)
	if err != nil {
		return contract.Contract{}, fmt.Errorf("%w: operation: %v", ErrInvalidMessage, err)
	}
	if intentDigest != c.Claims.IntentDigest {
		return contract.Contract{}, fmt.Errorf("%w: intent digest %s, contract binds %s", ErrContextMismatch, intentDigest, c.Claims.IntentDigest)
	}
	if opDigest != c.Claims.OperationDigest {
		return contract.Contract{}, fmt.Errorf("%w: operation digest %s, contract binds %s", ErrContextMismatch, opDigest, c.Claims.OperationDigest)
	}
	return c, nil
}

// transport is the transport the holder sends over.
func (h *Holder) transport() string {
	if h.Transport == "" {
		return contract.TransportHTTPS
	}
	return h.Transport
}

// checkInputLimits applies the draft 20.1 limits of the intent and the
// operation before anything is hashed or verified.
func checkInputLimits(intent core.Intent, op core.OperationContext) error {
	l := core.Defaults()
	if err := l.ValidateIntent(&intent); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := l.ValidateOperation(&op); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	return nil
}

// checkVersion reports a contract whose payload names another wire version
// as unsupported, so that it is not mistaken for a malformed one. The
// payload is not authenticated yet; Verify still checks it.
func checkVersion(compact string) error {
	payload, _, err := peek(compact)
	if err != nil {
		return nil // Verify reports the malformed JWS.
	}
	return versionOf(payload)
}

// translate maps an error of package contract to the sentinel of its code,
// keeping its text.
func translate(err error) error {
	code, _ := adapter.CodeOf(err)
	for _, s := range []error{ErrInvalidProof, ErrContextMismatch, ErrUnsupportedRequirement, ErrExpired, ErrDependencyUnavailable} {
		if c, _ := adapter.CodeOf(s); c == code {
			return fmt.Errorf("%w: %v", s, err)
		}
	}
	return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
}
