// Package ascii compares and lowercases protocol tokens over US-ASCII only.
//
// Schemes, hosts, field names, auth-schemes, coding names and the other
// tokens the module compares without regard to case are ASCII, and ABNF
// compares literal strings without regard to case over US-ASCII only (RFC
// 5234 2.3, B.1; RFC 3986 3.1, 3.2.2; RFC 9110 5.1, 11.1). The functions of
// package strings apply Unicode case mapping instead: strings.EqualFold folds
// U+212A KELVIN SIGN to "k" and U+017F LATIN SMALL LETTER LONG S to "s", and
// strings.ToLower maps U+212A to "k" and U+0130 LATIN CAPITAL LETTER I WITH
// DOT ABOVE to "i". A string with one of them is a different token, never the
// ASCII one it folds or lowercases to, so this package changes and folds the
// letters A-Z and a-z only and leaves every other byte as it is.
package ascii

// EqualFold reports whether s and t are equal when ASCII letters are compared
// without regard to case. Every other byte must match exactly.
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// ToLower returns s with the ASCII letters A-Z lowercased and every other byte
// unchanged.
func ToLower(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				b[j] = lower(b[j])
			}
			return string(b)
		}
	}
	return s
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
