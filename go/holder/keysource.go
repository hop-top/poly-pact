package holder

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"hop.top/pact-go/core/jws"
)

// KeySource holds the enrolled holder key (draft 6.2, 6.4). The private key
// never leaves it: the holder asks it for the public key and for a
// signature over a JWS signing input, so an OS keychain, a hardware key or
// a workload signing service can implement it.
type KeySource interface {
	// PublicJWK returns the public key, EC P-256 for ES256 or, where
	// negotiated, OKP Ed25519. It never carries private members.
	PublicJWK(ctx context.Context) (jws.JWK, error)
	// Sign returns the JWS signature over signingInput, the ASCII text of
	// the protected header and payload segments joined by a period (RFC
	// 7515 section 5.1), under the algorithm of the public key: the 64
	// octets R || S for ES256 (RFC 7518 section 3.4), the RFC 8032
	// signature for Ed25519.
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}

// MemoryKey is a KeySource over a private key in process memory, for tests
// and examples. It is not a protected key store: production holders keep
// their keys in one (draft 6.4).
type MemoryKey struct {
	es  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
	pub jws.JWK
}

// NewMemoryKeyES256 returns a MemoryKey for an ES256 (P-256) key.
func NewMemoryKeyES256(key *ecdsa.PrivateKey) (*MemoryKey, error) {
	if key == nil {
		return nil, errors.New("holder: nil ES256 key")
	}
	pub, err := jws.PublicJWK(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &MemoryKey{es: key, pub: pub}, nil
}

// NewMemoryKeyEd25519 returns a MemoryKey for an Ed25519 key.
func NewMemoryKeyEd25519(key ed25519.PrivateKey) (*MemoryKey, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("holder: Ed25519 private key of the wrong size")
	}
	pub, err := jws.PublicEd25519JWK(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &MemoryKey{ed: key, pub: pub}, nil
}

// PublicJWK implements KeySource: the key's kty, crv and coordinates, with
// no optional members.
func (k *MemoryKey) PublicJWK(context.Context) (jws.JWK, error) {
	return k.pub, nil
}

// Sign implements KeySource. ES256 signatures are randomized and written
// low-S, as jws.Sign writes them; Ed25519 signatures are deterministic.
func (k *MemoryKey) Sign(_ context.Context, signingInput []byte) ([]byte, error) {
	if k.ed != nil {
		return ed25519.Sign(k.ed, signingInput), nil
	}
	sum := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, k.es, sum[:])
	if err != nil {
		return nil, err
	}
	if n := elliptic.P256().Params().N; s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s.Sub(n, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}
