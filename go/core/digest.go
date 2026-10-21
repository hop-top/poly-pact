package core

import "fmt"

// DigestLen is the length of a base64url SHA-256 value without padding.
const DigestLen = 43

// Digest is a base64url (RFC 4648, no padding) SHA-256 value, such as an
// object digest or a JWK thumbprint. The schema pattern is ^[A-Za-z0-9_-]{43}$.
type Digest string

// Validate reports whether d is exactly 43 base64url characters.
func (d Digest) Validate() error {
	if len(d) != DigestLen {
		return fmt.Errorf("core: digest has %d bytes, want %d", len(d), DigestLen)
	}
	for i := range len(d) {
		c := d[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return fmt.Errorf("core: digest has invalid character %q at offset %d", c, i)
		}
	}
	return nil
}
