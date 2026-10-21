package ascii_test

import (
	"strings"
	"testing"

	"hop.top/pact-go/internal/ascii"
)

const (
	kelvin = "\u212A" // KELVIN SIGN: strings.EqualFold and strings.ToLower give "k"
	longS  = "\u017F" // LATIN SMALL LETTER LONG S: strings.EqualFold gives "s"
	dotI   = "\u0130" // LATIN CAPITAL LETTER I WITH DOT ABOVE: strings.ToLower gives "i"
)

func TestEqualFold(t *testing.T) {
	for _, c := range []struct {
		s, t string
		want bool
	}{
		{"https", "HTTPS", true},
		{"Bearer", "bEARER", true},
		{"", "", true},
		{"x-amz-date", "X-Amz-Date", true},
		{"chun" + kelvin + "ed", "chunked", false},
		{"http" + longS, "https", false},
		{"http" + longS, "HTTPS", false},
		{dotI + "dp", "idp", false},
		{"a", "b", false},
		{"https", "http", false},
		{"[", "{", false}, // 0x5B and 0x7B differ by 0x20 but are not letters
		{"@", "`", false},
	} {
		if got := ascii.EqualFold(c.s, c.t); got != c.want {
			t.Errorf("EqualFold(%q, %q) = %v, want %v", c.s, c.t, got, c.want)
		}
		if got := ascii.EqualFold(c.t, c.s); got != c.want {
			t.Errorf("EqualFold(%q, %q) = %v, want %v", c.t, c.s, got, c.want)
		}
	}
	// The cases strings.EqualFold gets wrong for protocol tokens.
	if !strings.EqualFold("http"+longS, "https") || !strings.EqualFold("chun"+kelvin+"ed", "chunked") {
		t.Fatal("strings.EqualFold no longer folds U+017F and U+212A; revisit the package doc")
	}
}

func TestToLower(t *testing.T) {
	for in, want := range map[string]string{
		"":                    "",
		"already-lower":       "already-lower",
		"Content-Type":        "content-type",
		"GRAPH.MICROSOFT.COM": "graph.microsoft.com",
		"PAC" + kelvin + "ED": "pac" + kelvin + "ed",
		dotI + "MPERSONATE-":  dotI + "mpersonate-",
		"X-" + longS + "IG":   "x-" + longS + "ig",
		"[\\]^_`{|}~@":        "[\\]^_`{|}~@",
		"\xff\xfeNot UTF-8 Z": "\xff\xfenot utf-8 z",
	} {
		if got := ascii.ToLower(in); got != want {
			t.Errorf("ToLower(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.ToLower(kelvin) != "k" || strings.ToLower(dotI) != "i" {
		t.Fatal("strings.ToLower no longer maps U+212A and U+0130 to ASCII; revisit the package doc")
	}
}
