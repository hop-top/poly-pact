package evalcase

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
)

// fillDigests sets, in the decoded payload, the member that each RFC 6901
// pointer of digests names to the artifact_digest (draft Section 7.4) of the
// signed file its path names, which an earlier entry signed, and returns the
// payload in RFC 8785 canonical form.
func fillDigests(payload []byte, digests map[string]string, signed map[string]signedArtifact) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	ptrs := make([]string, 0, len(digests))
	for p := range digests {
		ptrs = append(ptrs, p)
	}
	slices.Sort(ptrs)
	for _, ptr := range ptrs {
		a, ok := signed[digests[ptr]]
		if !ok {
			return nil, fmt.Errorf("digests %s: %s is not the signed file of an earlier entry", ptr, digests[ptr])
		}
		d, err := digest.ArtifactDigest(a.compact)
		if err != nil {
			return nil, err
		}
		if err := setPointer(doc, ptr, string(d)); err != nil {
			return nil, fmt.Errorf("digests %s: %w", ptr, err)
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return jcs.Canonicalize(b)
}

// setPointer sets the member or array element that the RFC 6901 pointer ptr
// names in doc to v. Every step but the last must exist; the last may add a
// member to an object, but only replace an element of an array.
func setPointer(doc any, ptr, v string) error {
	if !strings.HasPrefix(ptr, "/") {
		return fmt.Errorf("%q does not name a member", ptr)
	}
	tokens := strings.Split(ptr[1:], "/")
	cur := doc
	for i, tok := range tokens {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		last := i == len(tokens)-1
		switch c := cur.(type) {
		case map[string]any:
			if last {
				c[tok] = v
				return nil
			}
			next, ok := c[tok]
			if !ok {
				return fmt.Errorf("no member %q", tok)
			}
			cur = next
		case []any:
			n, err := strconv.Atoi(tok)
			if err != nil || n < 0 || n >= len(c) || strconv.Itoa(n) != tok {
				return fmt.Errorf("no array element %q", tok)
			}
			if last {
				c[n] = v
				return nil
			}
			cur = c[n]
		default:
			return fmt.Errorf("%q is inside a value that is not an object or array", tok)
		}
	}
	return nil
}
