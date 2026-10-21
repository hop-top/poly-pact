package source

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ErrNoJoin: a pushed record joins no principal. The source answers no fact
// for it and records it as a provisioning error.
var ErrNoJoin = errors.New("source: the record joins no principal")

// identifierRE is the identifier grammar of identity mapping section 3.1.
var identifierRE = regexp.MustCompile(`^(?:basic|oauth|saml|ldap|mtls|files|aws|k8s|db|x-[A-Za-z0-9-]+)(?::(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+)+$`)

// Join joins a pushed record to a principal. A pushed record names no
// principal: the source joins it by one declared join attribute whose value
// is the immutable local part of the principal's identifier in the
// authenticating mechanism's namespace (identity mapping IM-5), with the
// namespace and realm components taken from the source's configuration,
// never from the record (IM-4). Any other attribute of the record, such as
// a user name, an e-mail address or a display name, never joins.
//
// A record whose join value another record of the source also carries joins
// no principal either: the source that holds the records refuses it.
type Join struct {
	// Attribute is the declared join attribute, such as externalId.
	Attribute string
	// Prefix is the principal identifier up to its local part: the namespace
	// token and the realm components, each written as identity mapping IM-2
	// requires, and a final ":".
	Prefix string
}

// Principal returns the principal that a record with the attributes attrs
// joins: Prefix followed by the value of Attribute in the one spelling of
// IM-2. A record without the attribute, or whose value is empty or not
// UTF-8, is [ErrNoJoin]. A Join whose Attribute is empty or whose Prefix is
// not an identifier prefix is a configuration error.
func (j Join) Principal(attrs map[string]string) (string, error) {
	if j.Attribute == "" {
		return "", errors.New("source: no join attribute")
	}
	if !strings.HasSuffix(j.Prefix, ":") || !identifierRE.MatchString(j.Prefix+"x") {
		return "", fmt.Errorf("source: %q is not the prefix of an identifier", j.Prefix)
	}
	v, ok := attrs[j.Attribute]
	switch {
	case !ok:
		return "", fmt.Errorf("%w: no %s", ErrNoJoin, j.Attribute)
	case v == "":
		return "", fmt.Errorf("%w: %s is empty", ErrNoJoin, j.Attribute)
	case !utf8.ValidString(v):
		return "", fmt.Errorf("%w: %s is not UTF-8", ErrNoJoin, j.Attribute)
	}
	return j.Prefix + component(v), nil
}

// component writes the octets of v as an identifier component: an
// unreserved octet as it is, every other octet as %XX in upper-case
// hexadecimal (identity mapping IM-2).
func component(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
