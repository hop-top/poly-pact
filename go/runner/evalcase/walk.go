package evalcase

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
)

// File is one signed file of a directory as the generator contract defines
// it: what its compact JWS must carry and which key signs it.
type File struct {
	// Signed is the signed file, relative to the directory.
	Signed string
	Typ    string
	Key    Key
	// Payload is what the compact JWS carries: the decoded file, with its
	// digests set, or the presentation payload built from the case files.
	Payload []byte
	// Over is what the signature covers: Payload, or the payload_signed
	// file.
	Over []byte
	// Decoded is the artifact's decoded file, "" for a presentation.
	Decoded string
	// Digested is set when the artifact entry has digests: Payload is then
	// the decoded file with them set, which the generator writes back.
	// DigestsChanged reports that it differs from the decoded file read.
	Digested, DigestsChanged bool
}

// header is the protected header the generator writes for f: typ, and the
// kid of the signing key unless a holder signs (the key is then embedded).
func (f File) header() jws.Header {
	h := jws.Header{Typ: f.Typ, Kid: f.Key.Public.Kid}
	if role, _ := jws.TypRole(f.Typ); role == jws.RoleHolder {
		h.Kid = ""
	}
	return h
}

// Sign returns a fresh compact JWS for f: its protected header, Payload,
// and an ES256 signature over the header and Over. ES256 signatures are
// randomized, so two calls differ in the signature only.
func (f File) Sign() (string, error) {
	fresh, err := jws.Sign(f.header(), f.Over, f.Key.Private)
	if err != nil {
		return "", err
	}
	seg := strings.Split(fresh, ".")
	return seg[0] + "." + base64.RawURLEncoding.EncodeToString(f.Payload) + "." + seg[2], nil
}

// Check reports whether compact is a signed file the generator keeps for f
// (spec/v1.0/fixtures/README.md, section Signed artifacts): its protected header
// and payload are those Sign writes, and its signature verifies over them,
// over Over for a payload_signed entry, under f's key. A non-nil error says
// what is stale.
func (f File) Check(compact string) error {
	fresh, err := f.Sign()
	if err != nil {
		return err
	}
	if signingInput(compact) != signingInput(fresh) {
		return errors.New("stale: its protected header or payload is not the one the generator writes")
	}
	if !verifies(resigned(compact, f.Over), f.Typ, f.Key.Public) {
		return fmt.Errorf("stale: its signature does not verify under the %s key", f.Key.Role)
	}
	return nil
}

// resigned replaces the payload segment of compact with over, so that its
// signature can be checked over the payload it was computed on.
func resigned(compact string, over []byte) string {
	seg := strings.Split(compact, ".")
	if len(seg) != 3 {
		return compact
	}
	return seg[0] + "." + base64.RawURLEncoding.EncodeToString(over) + "." + seg[2]
}

func signingInput(compact string) string {
	i := strings.LastIndexByte(compact, '.')
	if i < 0 {
		return ""
	}
	return compact[:i]
}

// verifies reports whether compact verifies as typ under the public key
// jwk: by kid in a key set of the typ's role, or, for a holder, by the
// thumbprint of the embedded key.
func verifies(compact, typ string, jwk jws.JWK) bool {
	role, _ := jws.TypRole(typ)
	var res jws.StaticResolver
	if role == jws.RoleHolder {
		tp, err := jws.Thumbprint(jwk)
		if err != nil {
			return false
		}
		res.ExpectedHolderJKT = tp
	} else {
		set, err := jws.NewKeySet(jwk)
		if err != nil {
			return false
		}
		res.KeySets = map[jws.Role]*jws.KeySet{role: set}
	}
	_, err := jws.Verifier{Keys: res, Typ: typ}.Verify(compact)
	return err == nil
}

// signedArtifact is an artifact signed earlier in a walk: its compact JWS,
// the payload that the JWS carries, and its typ.
type signedArtifact struct {
	compact string
	payload []byte
	typ     string
}

// Walk applies the generator contract to the directory d of the fixture
// directory: for each entry of its signing.json, in order, it reads the
// decoded file (ReadDecoded), sets its digests, checks its jti and times,
// or builds the presentation payload (draft Section 11.2), and calls sign
// with the resulting File. sign returns the compact JWS that later entries
// embed or digest: the committed file or a fresh one.
func Walk(fixtures string, d Dir, keys map[string]Key, sign func(File) (string, error)) error {
	dir := filepath.Join(fixtures, filepath.FromSlash(d.Path))
	signed := map[string]signedArtifact{}
	var order []string
	for _, a := range d.Signing.Artifacts {
		payload, err := ReadDecoded(dir, a.Decoded)
		if err != nil {
			return err
		}
		if string(payload) == "null" {
			return fmt.Errorf("%s is null: a decoded file whose content is null has no artifact entry", a.Decoded)
		}
		f := File{Signed: a.Signed, Typ: a.Typ, Decoded: a.Decoded}
		if len(a.Digests) > 0 {
			filled, err := fillDigests(payload, a.Digests, signed)
			if err != nil {
				return fmt.Errorf("%s: %w", a.Decoded, err)
			}
			f.Digested, f.DigestsChanged = true, !bytes.Equal(filled, payload)
			payload = filled
		}
		if err := checkClaims(a, payload); err != nil {
			return err
		}
		over := payload
		if a.PayloadSigned != nil {
			if over, err = ReadDecoded(dir, *a.PayloadSigned); err != nil {
				return err
			}
		}
		k, ok := keys[a.Signer]
		if !ok {
			return fmt.Errorf("%s: no test key for role %s", a.Decoded, a.Signer)
		}
		f.Key, f.Payload, f.Over = k, payload, over
		compact, err := sign(f)
		if err != nil {
			return fmt.Errorf("%s: %w", a.Signed, err)
		}
		signed[a.Signed] = signedArtifact{compact: compact, payload: payload, typ: a.Typ}
		order = append(order, a.Signed)
	}
	for _, p := range d.Signing.Presentations {
		f, err := presentation(dir, p, signed, order, keys)
		if err == nil {
			_, err = sign(f)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", p.Signed, err)
		}
	}
	return nil
}

// presentation builds the presentation p from the case files and the
// artifacts signed before it (draft Section 11.2).
func presentation(dir string, p Presentation, signed map[string]signedArtifact, order []string, keys map[string]Key) (File, error) {
	var f File
	embedded := func(rel string) (signedArtifact, error) {
		a, ok := signed[rel]
		if !ok {
			return a, fmt.Errorf("%s is not the signed file of an artifact entry", rel)
		}
		return a, nil
	}
	contractPath := "signed/contract.jws"
	if p.Contract != nil {
		contractPath = *p.Contract
	}
	contract, err := embedded(contractPath)
	if err != nil {
		return f, fmt.Errorf("contract: %w", err)
	}
	var claims struct {
		PactVersion string `json:"pact_version"`
		Aud         string `json:"aud"`
		Nonce       string `json:"nonce"`
	}
	if err := json.Unmarshal(contract.payload, &claims); err != nil {
		return f, fmt.Errorf("contract %s: %w", contractPath, err)
	}
	evidence := []string{}
	var reputation any
	var reps []string
	for _, rel := range order {
		switch signed[rel].typ {
		case jws.TypEvidence:
			if p.Evidence == nil {
				evidence = append(evidence, signed[rel].compact)
			}
		case jws.TypReputation:
			reps = append(reps, rel)
		}
	}
	if p.Evidence != nil {
		for _, rel := range *p.Evidence {
			a, err := embedded(rel)
			if err != nil {
				return f, fmt.Errorf("evidence: %w", err)
			}
			evidence = append(evidence, a.compact)
		}
	}
	switch {
	case p.Reputation == nil && len(reps) > 1:
		return f, fmt.Errorf("reputation: %d snapshot artifacts; name one", len(reps))
	case p.Reputation == nil && len(reps) == 1:
		reputation = signed[reps[0]].compact
	case p.Reputation == nil, string(p.Reputation) == "null":
	default:
		var rel string
		if err := json.Unmarshal(p.Reputation, &rel); err != nil {
			return f, fmt.Errorf("reputation: not a path or null: %w", err)
		}
		a, err := embedded(rel)
		if err != nil {
			return f, fmt.Errorf("reputation: %w", err)
		}
		reputation = a.compact
	}

	parts := map[string][]byte{}
	for name, rel := range map[string]*string{"profile": p.Profile, "intent": p.Intent, "operation": p.Operation} {
		file := name + ".json"
		if rel != nil {
			file = *rel
		}
		b, err := ReadDecoded(dir, file)
		if err != nil {
			return f, err
		}
		parts[name] = b
	}
	var profile struct {
		AgentID  string `json:"agent_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(parts["profile"], &profile); err != nil {
		return f, fmt.Errorf("profile: %w", err)
	}
	iat := FixedTime
	if p.Iat != nil {
		iat = *p.Iat
	}
	nbf, exp := iat, iat+PresentationLifetime
	if p.Nbf != nil {
		nbf = *p.Nbf
	}
	if p.Exp != nil {
		exp = *p.Exp
	}
	payload, err := json.Marshal(map[string]any{
		"pact_version": claims.PactVersion,
		"iss":          profile.AgentID,
		"sub":          profile.AgentID,
		"aud":          claims.Aud,
		"jti":          p.JTI,
		"iat":          iat,
		"nbf":          nbf,
		"exp":          exp,
		"tenant_id":    profile.TenantID,
		"contract":     contract.compact,
		"profile":      json.RawMessage(parts["profile"]),
		"intent":       json.RawMessage(parts["intent"]),
		"operation":    json.RawMessage(parts["operation"]),
		"evidence":     evidence,
		"reputation":   reputation,
		"nonce":        claims.Nonce,
	})
	if err != nil {
		return f, err
	}
	if payload, err = jcs.Canonicalize(payload); err != nil {
		return f, err
	}
	k, ok := keys[p.Signer]
	if !ok {
		return f, fmt.Errorf("no test key for role %s", p.Signer)
	}
	return File{Signed: p.Signed, Typ: jws.TypPresentation, Key: k, Payload: payload, Over: payload}, nil
}

// ReadDecoded reads the decoded file rel of the directory dir, which must
// be RFC 8785 canonical with no trailing newline: it is the payload byte
// for byte.
func ReadDecoded(dir, rel string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	canon, err := jcs.Canonicalize(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if !bytes.Equal(canon, b) {
		return nil, fmt.Errorf("%s is not in RFC 8785 canonical form (no white space, sorted members, no trailing newline)", rel)
	}
	return b, nil
}

// checkClaims requires the entry's jti, iat, nbf and, when the entry states
// one, exp in a decoded artifact. iat defaults to FixedTime and nbf to the
// iat.
func checkClaims(a Artifact, payload []byte) error {
	var claims struct {
		JTI string `json:"jti"`
		Iat *int64 `json:"iat"`
		Nbf *int64 `json:"nbf"`
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("%s: %w", a.Decoded, err)
	}
	iat := FixedTime
	if a.Iat != nil {
		iat = *a.Iat
	}
	nbf := iat
	if a.Nbf != nil {
		nbf = *a.Nbf
	}
	differs := func(got *int64, want int64) bool { return got == nil || *got != want }
	show := func(v *int64) string {
		if v == nil {
			return "absent"
		}
		return fmt.Sprint(*v)
	}
	switch {
	case claims.JTI != a.JTI:
		return fmt.Errorf("%s: jti %q, want the fixed %q", a.Decoded, claims.JTI, a.JTI)
	case differs(claims.Iat, iat):
		return fmt.Errorf("%s: iat %s, want the fixed %d", a.Decoded, show(claims.Iat), iat)
	case differs(claims.Nbf, nbf):
		return fmt.Errorf("%s: nbf %s, want the fixed %d", a.Decoded, show(claims.Nbf), nbf)
	case a.Exp != nil && differs(claims.Exp, *a.Exp):
		return fmt.Errorf("%s: exp %s, want the fixed %d", a.Decoded, show(claims.Exp), *a.Exp)
	}
	return nil
}
