package evalcase

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// KeysFile is the file of the private test values, relative to the fixture
// directory.
const KeysFile = "keys/test-private-scalars.json"

// Key is an ES256 test key of KeysFile: its role, its private key, and its
// public JWK file, whose kid signed files carry.
type Key struct {
	Role    string
	Private *ecdsa.PrivateKey
	Public  jws.JWK
}

// LoadKeys reads the ES256 test keys of KeysFile under the fixture
// directory, by role, and checks each against its public JWK file: the
// public point and the kid must match. The Ed25519 pair is not listed.
func LoadKeys(fixtures string) (map[string]Key, error) {
	const file = KeysFile
	b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	var scalars struct {
		Label    string `json:"label"`
		Warning  string `json:"warning"`
		Encoding string `json:"encoding"`
		Keys     []struct {
			Role      string `json:"role"`
			Kid       string `json:"kid"`
			Alg       string `json:"alg"`
			Kty       string `json:"kty"`
			Crv       string `json:"crv"`
			Scalar    string `json:"scalar"`
			SeedHex   string `json:"seed_hex"`
			D         string `json:"d"`
			PublicJWK string `json:"public_jwk"`
		} `json:"keys"`
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &scalars); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	out := map[string]Key{}
	for _, k := range scalars.Keys {
		if k.Alg != jws.AlgES256 {
			continue // the Ed25519 pair is not an ES256 key
		}
		d, err := base64.RawURLEncoding.Strict().DecodeString(k.D)
		if err != nil {
			return nil, fmt.Errorf("%s: role %s: d: %w", file, k.Role, err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		if err != nil {
			return nil, fmt.Errorf("%s: role %s: %w", file, k.Role, err)
		}
		pubFile := filepath.Join(fixtures, "keys", filepath.FromSlash(k.PublicJWK))
		pb, err := os.ReadFile(pubFile)
		if err != nil {
			return nil, fmt.Errorf("%s: role %s: %w", file, k.Role, err)
		}
		jwk, err := jws.ParseJWK(pb)
		if err != nil {
			return nil, fmt.Errorf("keys/%s: %w", k.PublicJWK, err)
		}
		own, err := jws.PublicJWK(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		if own.X != jwk.X || own.Y != jwk.Y || jwk.Kid != k.Kid {
			return nil, fmt.Errorf("keys/%s is not the public key of role %s (kid %s)", k.PublicJWK, k.Role, k.Kid)
		}
		out[k.Role] = Key{Role: k.Role, Private: priv, Public: jwk}
	}
	return out, nil
}
