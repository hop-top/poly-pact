package jws

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"

	"hop.top/pact-go/core"
)

// KeySet is a set of trusted public keys, looked up by kid: ES256 keys and,
// in a set built by [Algorithms.NewKeySet], Ed25519 keys. It is built from
// configuration, never from an artifact; the zero value and a nil *KeySet
// are empty.
type KeySet struct {
	keys map[string]trustedKey
}

// trustedKey is a checked key: alg is the one algorithm it verifies, and
// exactly one of pub (ES256) and ed (Ed25519) is set.
type trustedKey struct {
	jwk        JWK
	alg        string
	pub        *ecdsa.PublicKey
	ed         ed25519.PublicKey
	thumbprint core.Digest
}

// newTrustedKey checks k for the algorithms algs, as ParseJWK does.
func newTrustedKey(k JWK, algs Algorithms) (trustedKey, error) {
	alg, err := k.check(algs)
	if err != nil {
		return trustedKey{}, err
	}
	t := trustedKey{jwk: k, alg: alg}
	if alg == AlgES256 {
		t.pub, err = k.PublicKey()
	} else {
		t.ed, err = k.Ed25519PublicKey()
	}
	if err != nil {
		return trustedKey{}, err
	}
	if t.thumbprint, err = Thumbprint(k); err != nil {
		return trustedKey{}, err
	}
	return t, nil
}

// NewKeySet checks each key as ParseJWK does and requires a non-empty kid,
// unique within the set. It is the baseline, ES256 keys alone; see
// [Algorithms.NewKeySet].
func NewKeySet(keys ...JWK) (*KeySet, error) {
	return newKeySet(nil, keys)
}

func newKeySet(algs Algorithms, keys []JWK) (*KeySet, error) {
	s := &KeySet{keys: make(map[string]trustedKey, len(keys))}
	for i, k := range keys {
		if k.Kid == "" {
			return nil, fail(ErrKidMissing, fmt.Sprintf("key %d has no kid", i), nil)
		}
		if _, dup := s.keys[k.Kid]; dup {
			return nil, fail(ErrKidDuplicate, fmt.Sprintf("kid %q", k.Kid), nil)
		}
		tk, err := newTrustedKey(k, algs)
		if err != nil {
			return nil, err
		}
		s.keys[k.Kid] = tk
	}
	return s, nil
}

// Lookup returns the key with the given kid.
func (s *KeySet) Lookup(kid string) (JWK, bool) {
	k, ok := s.lookup(kid)
	return k.jwk, ok
}

func (s *KeySet) lookup(kid string) (trustedKey, bool) {
	if s == nil || kid == "" {
		return trustedKey{}, false
	}
	k, ok := s.keys[kid]
	return k, ok
}

// KeyRequest describes the key one verification needs. It is built from the
// protected header and payload after their structural checks and before the
// signature is checked: nothing in it is authenticated yet. A resolver may use
// Header and Payload only to choose which configured trust record or
// enrollment binding applies (draft 7.3: iss selects a trust record), never to
// obtain key material.
type KeyRequest struct {
	// Typ is the artifact's typ and Role the signer role the draft 7.3 table
	// requires for it.
	Typ  string
	Role Role
	// Kid is the header kid, empty when absent.
	Kid string
	// Header and Payload are the decoded protected header and payload, as
	// received.
	Header  []byte
	Payload []byte
}

// KeyResolver supplies the trusted keys of a verification. Verify calls
// exactly one method, once: HolderJKT for RoleHolder, TrustedKeys for every
// other role. The package never fetches keys.
type KeyResolver interface {
	// TrustedKeys returns the key set trusted for req.Role. The header kid is
	// looked up in it and nowhere else. A nil set has no keys.
	TrustedKeys(req KeyRequest) (*KeySet, error)
	// HolderJKT returns the enrolled holder_jkt the embedded jwk of a
	// holder-signed artifact must match (draft 6.2, 7.2).
	HolderJKT(req KeyRequest) (core.Digest, error)
}

// StaticResolver is a KeyResolver over fixed configuration: one key set per
// role and one expected holder thumbprint.
type StaticResolver struct {
	KeySets           map[Role]*KeySet
	ExpectedHolderJKT core.Digest
}

// TrustedKeys returns KeySets[req.Role], nil when the role has none.
func (r StaticResolver) TrustedKeys(req KeyRequest) (*KeySet, error) {
	return r.KeySets[req.Role], nil
}

// HolderJKT returns ExpectedHolderJKT, or an error when it is empty.
func (r StaticResolver) HolderJKT(KeyRequest) (core.Digest, error) {
	if r.ExpectedHolderJKT == "" {
		return "", errors.New("no expected holder_jkt configured")
	}
	return r.ExpectedHolderJKT, nil
}
