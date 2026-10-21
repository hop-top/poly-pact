package jws

import (
	"encoding/base64"
	"fmt"
)

// b64 is unpadded base64url that, decoding, also requires the spare bits of
// the last character to be zero (RFC 4648 section 3.5).
var b64 = base64.RawURLEncoding.Strict()

// decodeSegment decodes s as RFC 7515 base64url: the URL-safe alphabet, no
// padding, no line breaks, white space or other characters (RFC 7515 sections
// 2 and 5.2), and only the canonical encoding of its octets. encoding/base64
// skips CR and LF even in strict mode, so the alphabet is checked first.
func decodeSegment(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, fmt.Errorf("character %q at offset %d is not base64url", c, i)
		}
	}
	return b64.DecodeString(s)
}
