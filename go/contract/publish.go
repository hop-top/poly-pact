package contract

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
)

// Signer signs a contract payload as a compact JWS of typ
// pact-requirements+jwt under the publisher's key. It signs the payload
// bytes exactly as given.
type Signer interface {
	SignContract(payload []byte) (string, error)
}

// ES256Signer signs contracts with an ES256 key whose kid the header names
// (draft 7.2).
type ES256Signer struct {
	Kid string
	Key *ecdsa.PrivateKey
}

// SignContract implements Signer.
func (s ES256Signer) SignContract(payload []byte) (string, error) {
	return jws.Sign(jws.Header{Typ: jws.TypRequirements, Kid: s.Kid}, payload, s.Key)
}

// Authenticated is the native context of the request a contract is issued
// for (draft 11.1 step 1): the principal that authenticate_native returned
// and the agent binding that resolve_agent_binding returned for the agent
// the request names (draft 17.1).
type Authenticated struct {
	Principal adapter.Principal
	Binding   adapter.AgentBinding
}

// Publisher is a gateway-authorized requirement publisher (draft 7.3, 9.1).
type Publisher struct {
	// Issuer is iss: the URI of the publisher's trust record.
	Issuer string
	// Audience is aud: the gateway the contracts are for.
	Audience string
	// Realm is the gateway's tenant and environment.
	Realm adapter.Realm
	// Signer signs the contracts and Replay registers their nonces.
	Signer Signer
	Replay ReplayStore
	// Lifetime is exp - iat, whole seconds from 1 s to 60 s; zero is 60 s
	// (draft 9.1, 20.1).
	Lifetime time.Duration
	// Purposes are the purpose identifiers of the gateway's installed
	// purpose mapping (draft 10.1). A request whose intent names another is
	// refused with ErrUnsupportedPurpose. Nil leaves the purpose to the
	// installed purpose/operation check of the evaluation (draft 11.3 step
	// 8).
	Purposes []string
	// ProtectedPaths are the profile paths that the installed mapping
	// (draft 17.2) classifies as identity, tenant membership, role
	// membership, delegation or approval; a self rule on one of them or on
	// a descendant is refused (Appendix A.2). The principal, delegation
	// and reputation paths are refused whatever it lists.
	ProtectedPaths []string
}

// Issue answers req with a signed contract at the publisher time now
// (draft 9.1, 11.1 steps 1 to 3). It refuses, issuing nothing:
//
//   - without native authentication (auth.Principal.ID empty) or an ACTIVE
//     binding of the agent and key that req names: ErrInvalidProof, or
//     ErrContextMismatch when the agent is enrolled for another workload
//     of the realm (draft 6.1, 17.1), or ErrSecurityHold when the binding
//     is marked compromised (draft 6.4, 9.1);
//   - when the principal's realm is not p.Realm, or req.Operation names
//     another principal or environment: ErrContextMismatch;
//   - when p.Purposes is not nil and does not list the purpose req.Intent
//     names: ErrUnsupportedPurpose (draft 10.1);
//   - when req carries extensions: ErrUnsupportedRequirement (draft 7.1);
//   - requirements that do not make a valid contract (Appendix A.2, A.3),
//     have no conservative set, select a set other than the conservative
//     one without SelectionConsistencyCheck in ContextChecks or without a
//     canonical field rule for each of r.Thresholds (draft 9.4), or hold
//     a self rule on a path of p.ProtectedPaths: ErrInvalidMessage.
//
// req.Operation is the operation context the gateway mapped from the
// request it authenticated (draft 10.2); the contract binds its
// object_digest and that of req.Intent. iat and nbf are now in whole
// seconds and exp is iat plus p.Lifetime. jti, contract_id and nonce are
// each 128 random bits. The payload is signed through p.Signer, and the
// nonce is registered in p.Replay until the later of exp and iat + 65 s
// (draft 7.5 with the baseline skew); a signer or store failure is
// ErrDependencyUnavailable, a nonce the store already holds an error that
// wraps ErrReplay. A Publisher with an empty Issuer, Audience or Realm
// member, no Signer or no Replay, or a Lifetime outside 1 to 60 whole
// seconds, issues nothing and returns an error that wraps no sentinel.
func (p *Publisher) Issue(ctx context.Context, req core.ContractRequest, auth Authenticated, r Requirements, now time.Time) (Contract, error) {
	lifetime, err := p.check()
	if err != nil {
		return Contract{}, err
	}
	if err := p.checkNative(req, auth); err != nil {
		return Contract{}, err
	}
	if p.Purposes != nil && !slices.Contains(p.Purposes, req.Intent.PurposeID) {
		return Contract{}, fmt.Errorf("%w: purpose %q", ErrUnsupportedPurpose, req.Intent.PurposeID)
	}
	if len(req.Extensions) > 0 {
		return Contract{}, fmt.Errorf("%w: contract request extensions", ErrUnsupportedRequirement)
	}
	if err := checkSelection(r); err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	if err := p.checkProtected(r.FieldRules); err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	opDigest, err := digest.ObjectDigest(req.Operation)
	if err != nil {
		return Contract{}, fmt.Errorf("%w: operation: %w", ErrInvalidMessage, err)
	}
	intentDigest, err := digest.ObjectDigest(req.Intent)
	if err != nil {
		return Contract{}, fmt.Errorf("%w: intent: %w", ErrInvalidMessage, err)
	}
	ids, err := randomIDs(3)
	if err != nil {
		return Contract{}, fmt.Errorf("%w: random: %w", ErrDependencyUnavailable, err)
	}
	iat := now.Unix()
	rules := r.FieldRules
	if rules == nil {
		rules = []core.FieldRule{}
	}
	claims := core.RequirementContract{
		PactVersion:            core.Version,
		Issuer:                 p.Issuer,
		Subject:                req.AgentID,
		Audience:               p.Audience,
		JTI:                    ids[0],
		IssuedAt:               iat,
		NotBefore:              iat,
		Expiry:                 iat + int64(lifetime/time.Second),
		TenantID:               p.Realm.TenantID,
		ContractID:             ids[1],
		EnvironmentID:          p.Realm.EnvironmentID,
		HolderJKT:              auth.Binding.HolderJKT,
		OperationDigest:        opDigest,
		IntentDigest:           intentDigest,
		BaseRevision:           r.Policy.BaseRevision,
		SelectedSet:            r.SelectedSet,
		FieldRules:             rules,
		ContextChecks:          r.ContextChecks,
		LearningPolicyDigest:   r.Policy.LearningPolicyDigest,
		LearningArtifactDigest: r.Policy.LearningArtifactDigest,
		Nonce:                  ids[2],
		Mode:                   r.Mode,
		Extensions:             r.Extensions,
	}
	if err := validate(claims); err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return Contract{}, fmt.Errorf("%w: encode: %w", ErrInvalidMessage, err)
	}
	compact, err := p.Signer.SignContract(payload)
	if err != nil {
		return Contract{}, fmt.Errorf("%w: sign: %w", ErrDependencyUnavailable, err)
	}
	if err := signedPayload(compact, payload); err != nil {
		return Contract{}, err
	}
	d, err := digest.ArtifactDigest(compact)
	if err != nil {
		return Contract{}, fmt.Errorf("contract: signer output: %w", err)
	}
	c := Contract{Compact: compact, Claims: claims, Digest: d}
	until := clock.ReplayRetention(claims.Expiry, claims.IssuedAt, clock.BaselineSkew)
	if err := p.Replay.Register(ctx, c.NonceRecord(), now, until); err != nil {
		if errors.Is(err, ErrReplay) || errors.Is(err, ErrDependencyUnavailable) {
			return Contract{}, fmt.Errorf("contract: register nonce: %w", err)
		}
		return Contract{}, fmt.Errorf("%w: register nonce: %w", ErrDependencyUnavailable, err)
	}
	return c, nil
}

// check validates the publisher's configuration and returns its lifetime.
func (p *Publisher) check() (time.Duration, error) {
	switch {
	case !bounded(p.Issuer, p.Audience, p.Realm.TenantID, p.Realm.EnvironmentID):
		return 0, errors.New("contract: publisher Issuer, Audience and Realm are required")
	case p.Signer == nil || p.Replay == nil:
		return 0, errors.New("contract: publisher Signer and Replay are required")
	}
	lifetime := p.Lifetime
	if lifetime == 0 {
		lifetime = 60 * time.Second
	}
	if max, _ := clock.MaxLifetime(clock.Contract); lifetime < time.Second || lifetime > max || lifetime%time.Second != 0 {
		return 0, fmt.Errorf("contract: lifetime %v is not 1 to 60 whole seconds", p.Lifetime)
	}
	return lifetime, nil
}

// checkNative applies draft 9.1: native authentication and a trustworthy
// binding of the agent and key the request names, in the publisher's realm.
func (p *Publisher) checkNative(req core.ContractRequest, auth Authenticated) error {
	b := auth.Binding
	switch {
	case auth.Principal.ID == "":
		return fmt.Errorf("%w: no native authentication", ErrInvalidProof)
	case auth.Principal.Realm != p.Realm:
		return fmt.Errorf("%w: principal realm %+v, publisher realm %+v", ErrContextMismatch, auth.Principal.Realm, p.Realm)
	case b.Status == adapter.BindingUnknown && b.EnrolledElsewhere:
		return fmt.Errorf("%w: agent enrolled for another workload", ErrContextMismatch)
	case b.Status == adapter.BindingCompromised:
		return fmt.Errorf("%w: agent binding %q", ErrSecurityHold, b.Status)
	case b.Status != adapter.BindingActive:
		return fmt.Errorf("%w: agent binding %q", ErrInvalidProof, b.Status)
	case b.AgentID != req.AgentID || b.HolderJKT != req.HolderJKT:
		return fmt.Errorf("%w: request names agent %q key %q, binding %q key %q", ErrInvalidProof, req.AgentID, req.HolderJKT, b.AgentID, b.HolderJKT)
	case req.Operation.PrincipalID != auth.Principal.ID:
		return fmt.Errorf("%w: operation principal %q, authenticated %q", ErrContextMismatch, req.Operation.PrincipalID, auth.Principal.ID)
	case req.Operation.EnvironmentID != p.Realm.EnvironmentID:
		return fmt.Errorf("%w: operation environment %q", ErrContextMismatch, req.Operation.EnvironmentID)
	}
	return nil
}

// checkSelection applies draft 9.4 (a) and (b).
func checkSelection(r Requirements) error {
	switch {
	case !bounded(r.ConservativeSet):
		return errors.New("the policy's conservative set is required")
	case r.SelectedSet == r.ConservativeSet:
		return nil
	case !slices.Contains(r.ContextChecks, SelectionConsistencyCheck):
		return fmt.Errorf("selected set %q is not the conservative set %q and context_checks lacks %s", r.SelectedSet, r.ConservativeSet, SelectionConsistencyCheck)
	}
	for i, t := range r.Thresholds {
		path, keyword, want, err := t.rule()
		if err != nil {
			return fmt.Errorf("thresholds[%d]: %w", i, err)
		}
		if !slices.ContainsFunc(r.FieldRules, func(fr core.FieldRule) bool {
			return fr.Source == core.RuleSourceEvidence && fr.Path == path && schemaKeyword(fr.Schema, keyword, want)
		}) {
			return fmt.Errorf("selected set %q has no evidence rule on %s with %s %s (draft 9.4 (b))", r.SelectedSet, path, keyword, want)
		}
	}
	return nil
}

// rule returns the canonical field rule of a threshold (draft 9.4 (b)): its
// path, and the schema keyword and the JSON value it must have.
func (t ThresholdRule) rule() (path, keyword, value string, err error) {
	minimum := t.Dimension != "" || t.Statistic != ""
	switch {
	case minimum && t.SecurityStatus != "":
		return "", "", "", errors.New("a threshold is a minimum or a security status, not both")
	case t.SecurityStatus != "":
		b, err := json.Marshal(t.SecurityStatus)
		return reputationPrefix + "/security_status", "const", string(b), err
	case t.Dimension == "" || t.Statistic == "":
		return "", "", "", errors.New("a minimum names a dimension and a statistic")
	}
	return reputationPrefix + "/dimensions/" + escape(t.Dimension) + "/" + escape(t.Statistic), "minimum", strconv.FormatInt(t.Minimum, 10), nil
}

// escape escapes a JSON Pointer reference token (RFC 6901).
func escape(token string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(token) }

// schemaKeyword reports whether the schema object has keyword with the JSON
// value want: numerically equal for a number, the same string for a
// string.
func schemaKeyword(schema json.RawMessage, keyword, want string) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(schema, &obj) != nil {
		return false
	}
	got, ok := obj[keyword]
	if !ok {
		return false
	}
	g, okG := new(big.Rat).SetString(string(bytes.TrimSpace(got)))
	w, okW := new(big.Rat).SetString(want)
	if okG && okW {
		return g.Cmp(w) == 0
	}
	var gs, ws string
	return json.Unmarshal(got, &gs) == nil && json.Unmarshal([]byte(want), &ws) == nil && gs == ws
}

// checkProtected refuses a self rule on a path of p.ProtectedPaths or a
// descendant of one (Appendix A.2).
func (p *Publisher) checkProtected(rules []core.FieldRule) error {
	for _, r := range rules {
		if r.Source != core.RuleSourceSelf {
			continue
		}
		for _, protected := range p.ProtectedPaths {
			if within(r.Path, protected) {
				return fmt.Errorf("a self rule cannot decide %s, which the installed mapping protects", r.Path)
			}
		}
	}
	return nil
}

// signedPayload checks that compact is a JWS of payload, so that Claims
// always describes what was signed.
func signedPayload(compact string, payload []byte) error {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return errors.New("contract: signer did not return a compact JWS")
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !bytes.Equal(got, payload) {
		return errors.New("contract: signer signed other bytes than the payload")
	}
	return nil
}

// randomIDs returns n identifiers of 128 random bits, base64url
// (Appendix A.2).
func randomIDs(n int) ([]string, error) {
	ids := make([]string, n)
	for i := range ids {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		ids[i] = base64.RawURLEncoding.EncodeToString(b)
	}
	return ids, nil
}
