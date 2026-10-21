package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// Verifier verifies received contracts.
type Verifier struct {
	// Publishers maps the iss of each gateway-authorized requirement
	// publisher to the keys its trust record holds (draft 7.3: iss selects
	// a trust record). A contract whose iss is not a key of the map has no
	// trusted key.
	Publishers map[string]*jws.KeySet
	// Algorithms are the negotiated JWS algorithms; nil is ES256 alone.
	Algorithms jws.Algorithms
	// Skew is the allowed clock skew, 0 to 5 s (draft 7.5); zero allows none.
	Skew time.Duration
}

// signatureReasons are the JWS failures that mean the publisher could not
// be authenticated; every other failure is a malformed message.
var signatureReasons = []jws.Reason{jws.ErrSignatureInvalid, jws.ErrKidUnknown, jws.ErrKeyUnavailable}

// Verify checks compact at the verifier time now, in this order, and
// returns the first failure:
//
//  1. the JWS profile of draft 7.2 with typ pact-requirements+jwt, and the
//     signature over the received signing input under a key of the trust
//     record iss names: ErrInvalidMessage for a malformed JWS or another
//     typ, ErrInvalidProof when no trusted key of that publisher verifies
//     it, which is the case for rules edited after signing;
//  2. strict decoding into a RequirementContract and the schema and
//     Appendix A.2 rules: ErrInvalidMessage;
//  3. the time rules of draft 7.5 with v.Skew: ErrExpired when now is at
//     or after exp, ErrInvalidMessage when iat or nbf is later than now
//     plus the skew or exp - iat exceeds 60 seconds (draft 9.1, 20.1).
//
// A skew outside 0 to 5 s is a configuration error, wrapping no sentinel.
// On error the Contract is empty.
func (v Verifier) Verify(compact string, now time.Time) (Contract, error) {
	if v.Skew < 0 || v.Skew > clock.BaselineSkew {
		return Contract{}, fmt.Errorf("contract: skew %v outside 0 to %v", v.Skew, clock.BaselineSkew)
	}
	parsed, err := jws.Verifier{Keys: publisherKeys(v.Publishers), Typ: jws.TypRequirements, Algorithms: v.Algorithms}.Verify(compact)
	if err != nil {
		if slices.Contains(signatureReasons, jws.ReasonOf(err)) {
			return Contract{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
		}
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	var claims core.RequirementContract
	if err := strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, &claims); err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	if err := validate(claims); err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	if err := clock.CheckWindow(claims.IssuedAt, claims.NotBefore, claims.Expiry, now, v.Skew); err != nil {
		if errors.Is(err, clock.ErrExpired) {
			return Contract{}, fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	if err := clock.CheckLifetime(clock.Contract, claims.IssuedAt, claims.Expiry); err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	d, err := digest.ArtifactDigest(compact)
	if err != nil {
		return Contract{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	return Contract{Compact: compact, Claims: claims, Digest: d}, nil
}

// publisherKeys resolves the key set of the trust record that the
// payload's iss names. The payload is not authenticated yet: iss only
// selects which configured keys apply (jws.KeyRequest).
type publisherKeys map[string]*jws.KeySet

func (p publisherKeys) TrustedKeys(req jws.KeyRequest) (*jws.KeySet, error) {
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(req.Payload, &claims); err != nil {
		return nil, nil
	}
	return p[claims.Iss], nil
}

func (publisherKeys) HolderJKT(jws.KeyRequest) (core.Digest, error) {
	return "", errors.New("a requirement contract is not holder-signed")
}
