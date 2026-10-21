package ldap

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// errProhibited is a password with a character SASLprep prohibits.
var errProhibited = errors.New("the password has a character SASLprep prohibits")

// preparePassword applies the mapping and the prohibited output steps of
// SASLprep (RFC 4013, sections 2.1 and 2.3) to a textual password, as RFC
// 4511, section 4.2 asks clients to do before a simple bind. Non-ASCII space
// characters (RFC 3454, table C.1.2) become SPACE, the characters commonly
// mapped to nothing (table B.1) are removed, and a character of tables C.1.2
// to C.9 that remains is an error. The result is what the adapter sends; an
// empty result is an empty password (profile LR-6). Normalization form KC
// (RFC 4013, section 2.2) and the bidirectional check (section 2.4) are not
// applied, so a password that they would change is sent as mapped and does
// not bind where the server stored the normalized form; that fails closed.
func preparePassword(p string) (string, error) {
	if !utf8.ValidString(p) {
		return "", errProhibited
	}
	var b strings.Builder
	for _, c := range p {
		switch {
		case inTable(c, tableB1):
			continue
		case inTable(c, tableC12):
			b.WriteRune(' ')
		case prohibited(c):
			return "", errProhibited
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), nil
}

type runeRange struct{ lo, hi rune }

func inTable(c rune, t []runeRange) bool {
	for _, r := range t {
		if c >= r.lo && c <= r.hi {
			return true
		}
	}
	return false
}

// prohibited reports whether c is in one of tables C.2.1 to C.9 of RFC 3454,
// the prohibited output of RFC 4013, section 2.3, other than C.1.2, which the
// mapping removes.
func prohibited(c rune) bool {
	for _, t := range [][]runeRange{tableC21, tableC22, tableC3, tableC4, tableC5, tableC6, tableC7, tableC8, tableC9} {
		if inTable(c, t) {
			return true
		}
	}
	return false
}

// RFC 3454, appendix B.1: commonly mapped to nothing.
var tableB1 = []runeRange{
	{0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x1806, 0x1806}, {0x180B, 0x180D},
	{0x200B, 0x200D}, {0x2060, 0x2060}, {0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF},
}

// RFC 3454, appendix C.1.2: non-ASCII space characters.
var tableC12 = []runeRange{
	{0x00A0, 0x00A0}, {0x1680, 0x1680}, {0x2000, 0x200B}, {0x202F, 0x202F},
	{0x205F, 0x205F}, {0x3000, 0x3000},
}

// RFC 3454, appendix C.2.1: ASCII control characters.
var tableC21 = []runeRange{{0x0000, 0x001F}, {0x007F, 0x007F}}

// RFC 3454, appendix C.2.2: non-ASCII control characters.
var tableC22 = []runeRange{
	{0x0080, 0x009F}, {0x06DD, 0x06DD}, {0x070F, 0x070F}, {0x180E, 0x180E},
	{0x200C, 0x200D}, {0x2028, 0x2029}, {0x2060, 0x2063}, {0x206A, 0x206F},
	{0xFEFF, 0xFEFF}, {0xFFF9, 0xFFFC}, {0x1D173, 0x1D17A},
}

// RFC 3454, appendix C.3: private use.
var tableC3 = []runeRange{{0xE000, 0xF8FF}, {0xF0000, 0xFFFFD}, {0x100000, 0x10FFFD}}

// RFC 3454, appendix C.4: non-character code points.
var tableC4 = []runeRange{
	{0xFDD0, 0xFDEF}, {0xFFFE, 0xFFFF}, {0x1FFFE, 0x1FFFF}, {0x2FFFE, 0x2FFFF},
	{0x3FFFE, 0x3FFFF}, {0x4FFFE, 0x4FFFF}, {0x5FFFE, 0x5FFFF}, {0x6FFFE, 0x6FFFF},
	{0x7FFFE, 0x7FFFF}, {0x8FFFE, 0x8FFFF}, {0x9FFFE, 0x9FFFF}, {0xAFFFE, 0xAFFFF},
	{0xBFFFE, 0xBFFFF}, {0xCFFFE, 0xCFFFF}, {0xDFFFE, 0xDFFFF}, {0xEFFFE, 0xEFFFF},
	{0xFFFFE, 0xFFFFF}, {0x10FFFE, 0x10FFFF},
}

// RFC 3454, appendix C.5: surrogate codes. A Go string that is valid UTF-8
// holds none; the table is kept for completeness.
var tableC5 = []runeRange{{0xD800, 0xDFFF}}

// RFC 3454, appendix C.6: inappropriate for plain text.
var tableC6 = []runeRange{{0xFFF9, 0xFFFD}}

// RFC 3454, appendix C.7: inappropriate for canonical representation.
var tableC7 = []runeRange{{0x2FF0, 0x2FFB}}

// RFC 3454, appendix C.8: change display properties or deprecated.
var tableC8 = []runeRange{
	{0x0340, 0x0341}, {0x200E, 0x200F}, {0x202A, 0x202E}, {0x206A, 0x206F},
}

// RFC 3454, appendix C.9: tagging characters.
var tableC9 = []runeRange{{0xE0001, 0xE0001}, {0xE0020, 0xE007F}}
