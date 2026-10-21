package conformance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/validator"
)

// privateKey is one entry of keys/test-private-scalars.json: published test
// values, never production keys.
type privateKey struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	D         string `json:"d"`
	PublicJWK string `json:"public_jwk"`
}

// loadPrivateKeys reads the test private values by public JWK file name.
func loadPrivateKeys(fixtures string) (map[string]privateKey, error) {
	b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(evalcase.KeysFile)))
	if err != nil {
		return nil, err
	}
	var f struct {
		Keys []privateKey `json:"keys"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	out := make(map[string]privateKey, len(f.Keys))
	for _, k := range f.Keys {
		out[k.PublicJWK] = k
	}
	return out, nil
}

// signerFor returns the signer of the validator key file keyFile (a path
// under the fixture directory, such as keys/validator.jwk.json).
func signerFor(keys map[string]privateKey, keyFile string) (validator.Signer, error) {
	k, ok := keys[path.Base(keyFile)]
	if !ok {
		return nil, fmt.Errorf("no private value for %s", keyFile)
	}
	d, err := base64.RawURLEncoding.DecodeString(k.D)
	if err != nil {
		return nil, err
	}
	switch k.Alg {
	case jws.AlgES256:
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		if err != nil {
			return nil, err
		}
		return validator.ES256Signer{Kid: k.Kid, Key: key}, nil
	case jws.AlgEd25519:
		return validator.Ed25519Signer{Kid: k.Kid, Key: ed25519.NewKeyFromSeed(d)}, nil
	}
	return nil, fmt.Errorf("%s: algorithm %q", keyFile, k.Alg)
}

// keySet reads public JWK files into a key set of the algorithms algs.
func keySet(fixtures string, algs jws.Algorithms, files []string) (*jws.KeySet, error) {
	keys := make([]jws.JWK, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		k, err := algs.ParseJWK(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		keys = append(keys, k)
	}
	return algs.NewKeySet(keys...)
}

// validatorConfig is config.json as the validator's trusted configuration.
func validatorConfig(fixtures string, c evalcase.Config) (validator.Config, error) {
	algs := c.Gateway.Algorithms()
	cfg := validator.Config{
		Audience:            c.Gateway.GatewayID,
		Realm:               realmOf(c),
		Issuer:              c.Validator.Iss,
		SourceID:            c.Validator.SourceID,
		Publishers:          map[string]*jws.KeySet{},
		Algorithms:          algs,
		Skew:                time.Duration(c.ClockSkewSeconds) * time.Second,
		Limits:              limitsOf(c.Limits),
		EvaluationTime:      time.Duration(c.Limits["evaluation_seconds"]) * time.Second,
		InstalledChecks:     c.InstalledChecks,
		SupportedExtensions: c.Gateway.ExtensionsSupported,
	}
	for _, t := range c.Trust {
		ks, err := keySet(fixtures, algs, t.Keys)
		if err != nil {
			return cfg, err
		}
		switch t.Role {
		case jws.RoleRequirementPublisher:
			cfg.Publishers[t.Iss] = ks
		case jws.RoleIssuer:
			cfg.Issuers = append(cfg.Issuers, validator.Issuer{ID: t.Iss, Keys: ks, ClaimPaths: t.ClaimPaths})
		case jws.RoleReputationService:
			cfg.ReputationServices = append(cfg.ReputationServices, validator.Issuer{ID: t.Iss, Keys: ks, ClaimPaths: t.ClaimPaths})
		}
	}
	for _, m := range c.NativeMappings {
		nm := validator.NativeMapping{Path: m.Path, NativePath: m.NativePath}
		if s := m.Source; s != nil {
			nm.Source = &validator.SourceCapability{
				SourceID: s.SourceID, BestMaxAgeSeconds: s.BestMaxAgeSeconds,
				BestStatusMaxAgeSeconds: s.BestStatusMaxAgeSeconds, LiveCheck: s.LiveCheck,
			}
		}
		cfg.NativeMappings = append(cfg.NativeMappings, nm)
	}
	return cfg, nil
}

func realmOf(c evalcase.Config) adapter.Realm {
	return adapter.Realm{TenantID: c.Gateway.TenantID, EnvironmentID: c.Gateway.EnvironmentID}
}

// limitsOf maps the metadata limits of draft 20.1 to the validator's; the
// evaluate transport bounds the presentation (draft 13.2).
func limitsOf(m map[string]int64) core.Limits {
	l := core.Defaults()
	set := func(dst *int, key string) {
		if v, ok := m[key]; ok && v > 0 && int(v) < *dst {
			*dst = int(v)
		}
	}
	set(&l.PresentationBytes, core.KeyMaxPresentationBytes)
	set(&l.PresentationBytes, "max_evaluate_presentation_bytes")
	set(&l.ArtifactPayloadBytes, "max_artifact_payload_bytes")
	set(&l.ProfileBytes, "max_profile_bytes")
	set(&l.EvidenceArtifacts, "max_evidence_artifacts")
	set(&l.FieldRules, "max_field_rules")
	set(&l.Depth, "max_json_depth")
	set(&l.Resources, "max_resources")
	set(&l.DescriptionBytes, "max_description_bytes")
	return l
}

// jwsPayload decodes the payload segment of a compact JWS, unverified.
func jwsPayload(compact string) ([]byte, bool) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	return b, err == nil
}

func artifactDigest(compact string) (core.Digest, error) { return digest.ArtifactDigest(compact) }
