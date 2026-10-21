package holder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// peek decodes the protected header typ and the payload of a compact JWS
// without verifying it. The holder reads the evidence and snapshots it was
// given only to select the ones a contract needs; the gateway verifies them
// under their issuers' authority (draft 11.2).
func peek(compact string) (payload []byte, typ string, err error) {
	seg := strings.Split(compact, ".")
	if len(seg) != 3 || seg[0] == "" || seg[1] == "" || seg[2] == "" {
		return nil, "", fmt.Errorf("not a compact JWS with an attached payload")
	}
	header, err := base64.RawURLEncoding.Strict().DecodeString(seg[0])
	if err != nil {
		return nil, "", fmt.Errorf("header: %v", err)
	}
	var h struct {
		Typ string `json:"typ"`
	}
	var members map[string]json.RawMessage
	if err := strictjson.Unmarshal(header, strictjson.Limits{}, &members); err != nil {
		return nil, "", fmt.Errorf("header: %v", err)
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return nil, "", fmt.Errorf("header typ: %v", err)
	}
	payload, err = base64.RawURLEncoding.Strict().DecodeString(seg[1])
	if err != nil {
		return nil, "", fmt.Errorf("payload: %v", err)
	}
	return payload, h.Typ, nil
}

// versionOf reports a payload whose pact_version is a string other than
// 0.1 (draft 21). Other defects are left to the strict decoding.
func versionOf(payload []byte) error {
	var v struct {
		PactVersion json.RawMessage `json:"pact_version"`
	}
	if json.Unmarshal(payload, &v) != nil {
		return nil
	}
	var s string
	if json.Unmarshal(v.PactVersion, &s) != nil {
		return nil
	}
	if s != core.Version {
		return fmt.Errorf("%w: pact_version %q, holder implements %q", ErrUnsupportedVersion, s, core.Version)
	}
	return nil
}

// artifact decodes the compact JWS of slot typ into v: the typ, the wire
// version, the draft 20.1 payload limit and strict decoding.
func artifact(compact, typ string, v any) ([]byte, error) {
	payload, got, err := peek(compact)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidMessage, typ, err)
	}
	if got != typ {
		return nil, fmt.Errorf("%w: typ %q in a %s slot", ErrInvalidMessage, got, typ)
	}
	if err := versionOf(payload); err != nil {
		return nil, err
	}
	if err := core.Defaults().ValidateArtifactSize(len(payload)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := strictjson.Unmarshal(payload, strictjson.Limits{}, v); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidMessage, typ, err)
	}
	return payload, nil
}

// evidence is an evidence artifact the agent holds.
type evidence struct {
	compact string
	claims  core.Evidence
}

// snapshot is a reputation snapshot the agent holds, with its value exactly
// as signed.
type snapshot struct {
	compact string
	claims  core.ReputationSnapshot
	value   json.RawMessage
}

func parseEvidence(compact string) (evidence, error) {
	var e core.Evidence
	if _, err := artifact(compact, jws.TypEvidence, &e); err != nil {
		return evidence{}, err
	}
	return evidence{compact: compact, claims: e}, nil
}

func parseSnapshot(compact string) (snapshot, error) {
	var s core.ReputationSnapshot
	payload, err := artifact(compact, jws.TypReputation, &s)
	if err != nil {
		return snapshot{}, err
	}
	var raw struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return snapshot{}, fmt.Errorf("%w: %s: %v", ErrInvalidMessage, jws.TypReputation, err)
	}
	return snapshot{compact: compact, claims: s, value: raw.Value}, nil
}

// pointer splits an RFC 6901 JSON Pointer into its unescaped reference
// tokens. The empty pointer, the whole document, is not a field path.
func pointer(p string) ([]string, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("path %q is not a JSON Pointer to a member", p)
	}
	tokens := strings.Split(p[1:], "/")
	for i, t := range tokens {
		for j := 0; j < len(t); j++ {
			if t[j] == '~' && (j+1 == len(t) || t[j+1] != '0' && t[j+1] != '1') {
				return nil, fmt.Errorf("path %q has an invalid escape", p)
			}
		}
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}

// lookup returns the value at tokens in the JSON document doc, and whether
// there is one (RFC 6901 section 4).
func lookup(doc json.RawMessage, tokens []string) (json.RawMessage, bool) {
	cur := doc
	for _, t := range tokens {
		switch firstByte(cur) {
		case '{':
			var m map[string]json.RawMessage
			if json.Unmarshal(cur, &m) != nil {
				return nil, false
			}
			v, ok := m[t]
			if !ok {
				return nil, false
			}
			cur = v
		case '[':
			var a []json.RawMessage
			if json.Unmarshal(cur, &a) != nil {
				return nil, false
			}
			i, ok := arrayIndex(t)
			if !ok || i >= len(a) {
				return nil, false
			}
			cur = a[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// arrayIndex parses an RFC 6901 array index: "0" or digits without a
// leading zero.
func arrayIndex(t string) (int, bool) {
	if t == "" || len(t) > 1 && t[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return 0, false
		}
	}
	i, err := strconv.Atoi(t)
	return i, err == nil
}

func firstByte(b json.RawMessage) byte {
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// sameJSON reports whether a and b are equal as JSON data: object member
// order is ignored, array order is significant (draft 8.4).
func sameJSON(a, b json.RawMessage) bool {
	ca, err := jcs.Canonicalize(a)
	if err != nil {
		return false
	}
	cb, err := jcs.Canonicalize(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ca, cb)
}
