package evalcase

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// Signed is a committed signed file of a directory, in signing.json order:
// the artifacts, then the presentations.
type Signed struct {
	// Path is the signed file, relative to the directory.
	Path    string
	Typ     string
	Compact string
	// Payload is the decoded payload the compact JWS carries.
	Payload []byte
	// Trust is nil when the compact JWS verifies against the directory's
	// trust records: for a service-signed artifact, under a key of a trust
	// record of the typ's signer role whose iss is the payload's iss; for a
	// presentation, by the embedded key whose thumbprint is the
	// authenticated holder_jkt of native_context.json. Otherwise it is the
	// failure, a *jws.Error whose reason jws.ReasonOf returns. A case may
	// fail it by design, as a payload_signed entry always does.
	Trust error
}

// Verify checks the committed signed files of the directory d against the
// generator contract and returns them, each with its Trust result. The
// trust records are the trust member of the directory's config.json; the
// holder_jkt, read when the directory has a presentation, is the
// authenticated member's of its native_context.json. Verify fails when a
// signed file is stale, that is not what the generator keeps (File.Check),
// or when a decoded file's digests are not those the generator sets.
func Verify(fixtures string, d Dir, keys map[string]Key) ([]Signed, error) {
	dir := filepath.Join(fixtures, filepath.FromSlash(d.Path))
	var cfg struct {
		Trust []TrustRecord `json:"trust"`
	}
	if err := readMember(filepath.Join(dir, "config.json"), "trust", &cfg.Trust); err != nil {
		return nil, fmt.Errorf("%s/config.json: %w", d.ID, err)
	}
	var jkt core.Digest
	if len(d.Signing.Presentations) > 0 {
		var auth *Authenticated
		if err := readMember(filepath.Join(dir, "native_context.json"), "authenticated", &auth); err != nil {
			return nil, fmt.Errorf("%s/native_context.json: %w", d.ID, err)
		}
		if auth != nil {
			jkt = deref(auth.HolderJKT)
		}
	}
	return verify(fixtures, d, keys, cfg.Trust, jkt)
}

// readMember decodes the member name of the strict JSON object file p into
// v. A missing file or member leaves v unchanged.
func readMember(p, name string, v any) error {
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var obj map[string]json.RawMessage
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &obj); err != nil {
		return err
	}
	raw, ok := obj[name]
	if !ok {
		return nil
	}
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func verify(fixtures string, d Dir, keys map[string]Key, trust []TrustRecord, holderJKT core.Digest) ([]Signed, error) {
	dir := filepath.Join(fixtures, filepath.FromSlash(d.Path))
	var out []Signed
	err := Walk(fixtures, d, keys, func(f File) (string, error) {
		if f.DigestsChanged {
			return "", fmt.Errorf("stale: the digests of %s are not the artifact_digest values of the files they name; run pactfix generate", f.Decoded)
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Signed)))
		if err != nil {
			return "", err
		}
		compact := string(b)
		if err := f.Check(compact); err != nil {
			return "", err
		}
		out = append(out, Signed{
			Path: f.Signed, Typ: f.Typ, Compact: compact, Payload: f.Payload,
			Trust: trusted(fixtures, compact, f.Typ, f.Payload, trust, holderJKT),
		})
		return compact, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", d.ID, err)
	}
	return out, nil
}

// trusted verifies compact as typ against the trust records and the
// enrolled holder_jkt.
func trusted(fixtures, compact, typ string, payload []byte, trust []TrustRecord, holderJKT core.Digest) error {
	role, _ := jws.TypRole(typ)
	var res jws.StaticResolver
	if role == jws.RoleHolder {
		res.ExpectedHolderJKT = holderJKT
	} else {
		var claims struct {
			Iss string `json:"iss"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return err
		}
		var set []jws.JWK
		for _, r := range trust {
			if r.Role != role || r.Iss != claims.Iss {
				continue
			}
			for _, k := range r.Keys {
				b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(k)))
				if err != nil {
					return err
				}
				jwk, err := jws.ParseJWK(b)
				if err != nil {
					return fmt.Errorf("%s: %w", k, err)
				}
				if !containsKid(set, jwk) {
					set = append(set, jwk)
				}
			}
		}
		ks, err := jws.NewKeySet(set...)
		if err != nil {
			return err
		}
		res.KeySets = map[jws.Role]*jws.KeySet{role: ks}
	}
	_, err := jws.Verifier{Keys: res, Typ: typ}.Verify(compact)
	return err
}

// containsKid reports whether set holds k. Two records of one role and iss
// may name the same key file.
func containsKid(set []jws.JWK, k jws.JWK) bool {
	for _, s := range set {
		if s.Kid == k.Kid && s.X == k.X && s.Y == k.Y {
			return true
		}
	}
	return false
}
