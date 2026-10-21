package ldap_test

import (
	"testing"

	"hop.top/pact-go/adapters/ldap"
)

// TestEntryValuesFoldASCII: attribute descriptions are ASCII keystrings
// compared without regard to case (RFC 4512 1.4, 2.5), so
// "\u017FAMAccountName" (U+017F LATIN SMALL LETTER LONG S, which
// strings.EqualFold folds to "s") is not sAMAccountName.
func TestEntryValuesFoldASCII(t *testing.T) {
	e := ldap.Entry{Attributes: []ldap.Attribute{{Name: "\u017FAMAccountName", Values: [][]byte{[]byte("x")}}}}
	if v := e.Values("sAMAccountName"); v != nil {
		t.Errorf("Values(sAMAccountName) = %q from an attribute with U+017F", v)
	}
	e = ldap.Entry{Attributes: []ldap.Attribute{{Name: "SAMACCOUNTNAME", Values: [][]byte{[]byte("x")}}}}
	if v := e.Values("sAMAccountName"); len(v) != 1 {
		t.Errorf("Values(sAMAccountName) = %q from an ASCII case variant", v)
	}
}
