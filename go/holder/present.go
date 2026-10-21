package holder

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
)

// Input is what a presentation is built from.
type Input struct {
	// Contract is the compact requirement contract the gateway returned.
	Contract string
	// Intent and Operation are the declared intent and the operation the
	// agent is about to perform; the contract must bind both.
	Intent    core.Intent
	Operation core.OperationContext
	// Profile is the agent's source profile: the core fields of the view to
	// disclose and every attribute the agent holds. Only the attributes the
	// contract requires are disclosed.
	Profile core.AgentProfile
	// Evidence holds the compact evidence artifacts the agent obtained from
	// issuers; only those an evidence rule uses are attached.
	Evidence []string
	// Reputation is the compact reputation snapshot the agent obtained, ""
	// for none; it is attached only when a rule requires it.
	Reputation string
}

// Presentation is a signed presentation.
type Presentation struct {
	// Compact is the compact JWS of typ pact-presentation+jwt.
	Compact string
	// Claims is its payload.
	Claims core.Presentation
	// Contract is the verified contract it embeds.
	Contract contract.Contract
	// Digest is the artifact_digest of Compact, ProfileDigest the
	// object_digest of the disclosed profile (draft 7.4, Appendix A.2).
	Digest        core.Digest
	ProfileDigest core.Digest
}

// presentationHeader is the protected header of a presentation: alg, typ and
// the embedded public key, which the gateway accepts only after matching the
// enrolled holder_jkt (draft 7.2). It carries no kid.
type presentationHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	JWK *jws.JWK `json:"jwk"`
}

// Present builds and signs the presentation of in at the holder time now
// (draft 11.1 steps 4 and 5, 11.2):
//
//  1. the contract, through [Holder.VerifyContract]: publisher, freshness,
//     agent, gateway, realm, extensions, holder key, intent and operation;
//  2. the source profile names this agent, key and tenant and is current,
//     its lifetime at most 24 hours (draft 8.1, Appendix A.2);
//  3. the view discloses the core fields and, of the attributes, only the
//     values the contract's field rules name, in rule order (draft 8.1, 9.2,
//     19). A native or self rule takes the profile's value. An evidence rule
//     needs an applicable evidence claim on exactly its path, from an issuer
//     the rule allows, for this agent, key, gateway and realm, valid now
//     (draft 8.3, 8.4): every applicable claim must equal the profile's
//     value or, when the profile has none, one another, and then supplies
//     it. An evidence rule at or under /attributes/reputation takes the
//     complete value of an applicable snapshot (draft 15.2). A rule the
//     agent cannot satisfy fails with ErrMissingField, a value that
//     disagrees with the evidence with ErrConflictingEvidence; nothing is
//     self-asserted in place of an authoritative value (draft 8.6);
//  4. the evidence that backs a rule is attached in input order, the
//     snapshot only when a rule uses it, and the draft 20.1 limits hold
//     (ErrInvalidMessage: nothing is truncated or dropped to fit);
//  5. the payload, iss and sub the agent, aud the gateway, a fresh 128-bit
//     jti, iat and nbf now, exp iat plus h.Lifetime, the contract's nonce,
//     is RFC 8785 canonical JSON, and the key source signs the protected
//     header and payload. The holder verifies the result under the key's
//     thumbprint before returning it (ErrInvalidProof).
//
// Malformed evidence or snapshots are ErrInvalidMessage, or
// ErrUnsupportedVersion for another wire version. A key source or random
// source failure is ErrDependencyUnavailable.
func (h *Holder) Present(ctx context.Context, in Input, now time.Time) (Presentation, error) {
	lifetime, err := h.check()
	if err != nil {
		return Presentation{}, err
	}
	k, err := h.key(ctx)
	if err != nil {
		return Presentation{}, err
	}
	c, err := h.verifyContract(in.Contract, in.Intent, in.Operation, k, now)
	if err != nil {
		return Presentation{}, err
	}
	if err := h.checkProfile(in.Profile, k, now); err != nil {
		return Presentation{}, err
	}
	view, ev, rep, err := h.view(in, c, k, now)
	if err != nil {
		return Presentation{}, err
	}
	jti, err := h.jti()
	if err != nil {
		return Presentation{}, err
	}
	iat := now.Unix()
	claims := core.Presentation{
		PactVersion: core.Version,
		Issuer:      h.AgentID,
		Subject:     h.AgentID,
		Audience:    h.Gateway,
		JTI:         jti,
		IssuedAt:    iat,
		NotBefore:   iat,
		Expiry:      iat + lifetime,
		TenantID:    h.Realm.TenantID,
		Contract:    c.Compact,
		Profile:     view,
		Intent:      in.Intent,
		Operation:   in.Operation,
		Evidence:    ev,
		Reputation:  rep,
		Nonce:       c.Claims.Nonce,
	}
	payload, err := canonicalJSON(claims)
	if err != nil {
		return Presentation{}, err
	}
	if err := core.Defaults().ValidatePresentation(&claims, len(payload)); err != nil {
		return Presentation{}, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	compact, err := h.sign(ctx, k, payload)
	if err != nil {
		return Presentation{}, err
	}
	d, err := digest.ArtifactDigest(compact)
	if err != nil {
		return Presentation{}, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	pd, err := digest.ObjectDigest(view)
	if err != nil {
		return Presentation{}, fmt.Errorf("%w: profile: %v", ErrInvalidMessage, err)
	}
	return Presentation{Compact: compact, Claims: claims, Contract: c, Digest: d, ProfileDigest: pd}, nil
}

// view builds the disclosed profile and selects the evidence and snapshot
// it needs.
func (h *Holder) view(in Input, c contract.Contract, k holderKey, now time.Time) (core.AgentProfile, []string, *string, error) {
	d := &disclosure{h: h, key: k, now: now, sourceAt: in.Profile.Attributes}
	var err error
	if d.source, err = json.Marshal(in.Profile); err != nil {
		return core.AgentProfile{}, nil, nil, fmt.Errorf("%w: profile: %v", ErrInvalidMessage, err)
	}
	for _, compact := range in.Evidence {
		e, err := parseEvidence(compact)
		if err != nil {
			return core.AgentProfile{}, nil, nil, err
		}
		d.evidence = append(d.evidence, e)
	}
	if in.Reputation != "" {
		s, err := parseSnapshot(in.Reputation)
		if err != nil {
			return core.AgentProfile{}, nil, nil, err
		}
		d.snap = &s
	}
	attrs, err := d.disclose(c.Claims.FieldRules)
	if err != nil {
		return core.AgentProfile{}, nil, nil, err
	}
	view := in.Profile
	view.Attributes = attrs
	b, err := canonicalJSON(view)
	if err != nil {
		return core.AgentProfile{}, nil, nil, err
	}
	if err := core.Defaults().ValidateProfileSize(len(b)); err != nil {
		return core.AgentProfile{}, nil, nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	ev := []string{}
	for i, e := range d.evidence {
		if d.used[i] && !slices.Contains(ev, e.compact) {
			ev = append(ev, e.compact)
		}
	}
	var rep *string
	if d.snapUsed {
		rep = &d.snap.compact
	}
	return view, ev, rep, nil
}

// jti returns 128 random bits, base64url without padding (Appendix A.2).
func (h *Holder) jti() (string, error) {
	r := h.Random
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("%w: random: %v", ErrDependencyUnavailable, err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sign has the key source sign the presentation and verifies its signature
// as the gateway will: the embedded key's thumbprint is the holder key's
// (draft 6.2, 7.2).
func (h *Holder) sign(ctx context.Context, k holderKey, payload []byte) (string, error) {
	jwk := k.jwk
	header, err := json.Marshal(presentationHeader{Alg: k.alg, Typ: jws.TypPresentation, JWK: &jwk})
	if err != nil {
		return "", fmt.Errorf("%w: header: %v", ErrInvalidMessage, err)
	}
	b64 := base64.RawURLEncoding
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sig, err := h.Keys.Sign(ctx, []byte(input))
	if err != nil {
		return "", fmt.Errorf("%w: key source: %v", ErrDependencyUnavailable, err)
	}
	compact := input + "." + b64.EncodeToString(sig)
	v := jws.Verifier{Keys: jws.StaticResolver{ExpectedHolderJKT: k.jkt}, Typ: jws.TypPresentation, Algorithms: h.Algorithms}
	if _, err := v.Verify(compact); err != nil {
		return "", fmt.Errorf("%w: the key source's signature does not verify under its key: %v", ErrInvalidProof, err)
	}
	return compact, nil
}

// canonicalJSON returns the RFC 8785 form of v.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	b, err := jcs.Canonicalize(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	return b, nil
}
