package digest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jcs"
)

// ErrNotObject is returned by ObjectDigest for a value that does not encode to
// a JSON object.
var ErrNotObject = errors.New("digest: value is not a JSON object")

// ObjectDigest returns object_digest(v): the base64url SHA-256 of the RFC 8785
// canonical form of the JSON encoding of v. See the package documentation for
// the checks applied and for passing received JSON as json.RawMessage. On
// error the digest is empty.
func ObjectDigest(v any) (core.Digest, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The size limit applies to the text read back, so an escape such as
	// < for '<' must not count against it.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("digest: encode: %w", err)
	}
	text := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	// Encoder output is compact, so the first byte tells the JSON type.
	if len(text) == 0 || text[0] != '{' {
		return "", ErrNotObject
	}
	canonical, err := jcs.Canonicalize(text)
	if err != nil {
		return "", fmt.Errorf("digest: %w", err)
	}
	return BytesDigest(canonical), nil
}

// ArtifactDigest returns artifact_digest(s): the base64url SHA-256 of the ASCII
// bytes of the compact JWS string s, exactly as given. It returns an error for
// a string with a byte outside ASCII. On error the digest is empty.
func ArtifactDigest(s string) (core.Digest, error) {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return "", fmt.Errorf("digest: artifact has non-ASCII byte 0x%02x at offset %d", s[i], i)
		}
	}
	return BytesDigest([]byte(s)), nil
}

// BytesDigest returns bytes_digest(b): the base64url SHA-256 of b, without
// padding. A nil slice and an empty slice give the same digest.
func BytesDigest(b []byte) core.Digest {
	sum := sha256.Sum256(b)
	return core.Digest(base64.RawURLEncoding.EncodeToString(sum[:]))
}
