package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// keyScalarsPath is the file of private test values, relative to the
// fixture directory (spec/v1.0/fixtures/keys/README.md).
const keyScalarsPath = "keys/test-private-scalars.json"

// appendixCHolderJKT is the holder_jkt of draft Appendix C: the RFC 7638
// thumbprint of the holder key, P-256 scalar 1.
const appendixCHolderJKT core.Digest = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"

// keyScalars is keys/test-private-scalars.json.
type keyScalars struct {
	Label    string      `json:"label"`
	Warning  string      `json:"warning"`
	Encoding string      `json:"encoding"`
	Keys     []keyRecord `json:"keys"`
}

// keyRecord is the private value of one test key. A P-256 record carries
// scalar, an Ed25519 record seed_hex.
type keyRecord struct {
	Role      string  `json:"role"`
	Kid       string  `json:"kid"`
	Alg       string  `json:"alg"`
	Kty       string  `json:"kty"`
	Crv       string  `json:"crv"`
	Scalar    *string `json:"scalar"`
	SeedHex   *string `json:"seed_hex"`
	D         string  `json:"d"`
	PublicJWK string  `json:"public_jwk"`
}

// jwkPath is the public JWK file of the record, relative to the fixture
// directory.
func (k keyRecord) jwkPath() string { return path.Join(path.Dir(keyScalarsPath), k.PublicJWK) }

func (k keyRecord) p256() bool { return k.Kty == "EC" && k.Crv == "P-256" }

// runKeyEntry applies the key rule to a key entry. A P-256 JWK passes when
// it parses as a public key and its point is its record's scalar times the
// base point, and, for the record of role holder, when its thumbprint is
// the holder_jkt of Appendix C. An Ed25519 JWK is out of scope: Ed25519 is
// optional (draft section 7.2) and nothing here verifies it. The entry of
// the scalars file passes when every P-256 record derives and a record of
// role holder exists.
func runKeyEntry(root string, e vectorEntry) error {
	var scalars keyScalars
	if _, err := readFixtureJSON(root, keyScalarsPath, &scalars); err != nil {
		return err
	}
	if e.Path == keyScalarsPath {
		holder := false
		for _, k := range scalars.Keys {
			if !k.p256() {
				continue
			}
			if err := checkKeyRecord(root, k); err != nil {
				return fmt.Errorf("record of role %s: %w", k.Role, err)
			}
			holder = holder || k.Role == "holder"
		}
		if !holder {
			return fmt.Errorf("no P-256 record of role holder, the key of Appendix C holder_jkt")
		}
		return nil
	}

	var head struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
	}
	raw, err := readFixture(root, e.Path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	if head.Kty == "OKP" && head.Crv == "Ed25519" {
		return skipped{reason: reasonOutOfScope, msg: "Ed25519 key: the algorithm is optional (draft section 7.2) and not verified here"}
	}
	for _, k := range scalars.Keys {
		if k.jwkPath() == e.Path {
			return checkKeyRecord(root, k)
		}
	}
	return fmt.Errorf("no record in %s names %s", keyScalarsPath, path.Base(e.Path))
}

// checkKeyRecord derives the public point of a P-256 record from its d,
// which must be its scalar as 32 big-endian octets, and compares it with
// the record's public JWK.
func checkKeyRecord(root string, k keyRecord) error {
	if !k.p256() {
		return fmt.Errorf("kty %q crv %q, want EC P-256", k.Kty, k.Crv)
	}
	d, err := base64.RawURLEncoding.DecodeString(k.D)
	if err != nil || len(d) != 32 {
		return fmt.Errorf("d is not 32 octets of base64url")
	}
	n, ok := new(big.Int).SetString(deref(k.Scalar), 10)
	if !ok || n.Sign() <= 0 || n.BitLen() > 256 {
		return fmt.Errorf("scalar %q is not a positive decimal integer", deref(k.Scalar))
	}
	if new(big.Int).SetBytes(d).Cmp(n) != 0 {
		return fmt.Errorf("d is not scalar %s as 32 big-endian octets", n)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return fmt.Errorf("scalar %s: %w", n, err)
	}
	want, err := jws.PublicJWK(&priv.PublicKey)
	if err != nil {
		return err
	}
	raw, err := readFixture(root, k.jwkPath())
	if err != nil {
		return err
	}
	got, err := jws.ParseJWK(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", k.jwkPath(), err)
	}
	if got.X != want.X || got.Y != want.Y {
		return fmt.Errorf("%s: public point x=%s y=%s, but scalar %s times G is x=%s y=%s", k.jwkPath(), got.X, got.Y, n, want.X, want.Y)
	}
	if k.Role == "holder" {
		tp, err := jws.Thumbprint(got)
		if err != nil {
			return fmt.Errorf("%s: %w", k.jwkPath(), err)
		}
		if tp != appendixCHolderJKT {
			return fmt.Errorf("%s: holder thumbprint %s, want Appendix C holder_jkt %s", k.jwkPath(), tp, appendixCHolderJKT)
		}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
