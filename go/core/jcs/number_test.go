package jcs

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

// appendixB lists the number serialization samples of RFC 8785 Appendix B,
// less NaN and Infinity, which JSON cannot carry (see TestAppendNumberNonFinite).
var appendixB = []struct {
	bits uint64
	want string
}{
	{0x0000000000000000, "0"},
	{0x8000000000000000, "0"},
	{0x0000000000000001, "5e-324"},
	{0x8000000000000001, "-5e-324"},
	{0x7fefffffffffffff, "1.7976931348623157e+308"},
	{0xffefffffffffffff, "-1.7976931348623157e+308"},
	{0x4340000000000000, "9007199254740992"},
	{0xc340000000000000, "-9007199254740992"},
	{0x4430000000000000, "295147905179352830000"},
	{0x44b52d02c7e14af5, "9.999999999999997e+22"},
	{0x44b52d02c7e14af6, "1e+23"},
	{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
	{0x444b1ae4d6e2ef4e, "999999999999999700000"},
	{0x444b1ae4d6e2ef4f, "999999999999999900000"},
	{0x444b1ae4d6e2ef50, "1e+21"},
	{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
	{0x3eb0c6f7a0b5ed8d, "0.000001"},
	{0x41b3de4355555553, "333333333.3333332"},
	{0x41b3de4355555554, "333333333.33333325"},
	{0x41b3de4355555555, "333333333.3333333"},
	{0x41b3de4355555556, "333333333.3333334"},
	{0x41b3de4355555557, "333333333.33333343"},
	{0xbecbf647612f3696, "-0.0000033333333333333333"},
	{0x43143ff3c1cb0959, "1424953923781206.2"},
}

func format(t *testing.T, f float64) string {
	t.Helper()
	b, err := appendNumber(nil, f)
	if err != nil {
		t.Fatalf("appendNumber(%v): %v", f, err)
	}
	return string(b)
}

func TestAppendNumberAppendixB(t *testing.T) {
	for _, tc := range appendixB {
		f := math.Float64frombits(tc.bits)
		if got := format(t, f); got != tc.want {
			t.Errorf("%016x: got %q, want %q", tc.bits, got, tc.want)
		}
	}
}

// The ES6 layout switches at 10^21 and 10^-6; the exponent form carries an
// explicit sign and no padding. Expected values come from V8 (JSON.stringify).
func TestAppendNumberLayout(t *testing.T) {
	tenth, fifth := 0.1, 0.2
	tests := []struct {
		f    float64
		want string
	}{
		{1e21, "1e+21"},
		{-1e21, "-1e+21"},
		{9.999999999999999e20, "999999999999999900000"},
		{1e20, "100000000000000000000"},
		{1.23e20, "123000000000000000000"},
		{123456789012345680000, "123456789012345680000"},
		{1.5e25, "1.5e+25"},
		{1e100, "1e+100"},
		{math.Pow(2, 70), "1.1805916207174113e+21"},
		{1e15, "1000000000000000"},
		{100, "100"},
		{123, "123"},
		{22, "22"},
		{12.5, "12.5"},
		{1234.5678, "1234.5678"},
		{0.5, "0.5"},
		{1.0 / 3, "0.3333333333333333"},
		{tenth + fifth, "0.30000000000000004"}, // a constant sum would be exact: 0.3
		{1e-6, "0.000001"},
		{2e-6, "0.000002"},
		{1.5e-6, "0.0000015"},
		{4.5e-6, "0.0000045"},
		{0.000123, "0.000123"},
		{9.999999999999997e-7, "9.999999999999997e-7"},
		{5e-7, "5e-7"},
		{1e-7, "1e-7"},
		{1.5e-7, "1.5e-7"},
		{-1.5e-7, "-1.5e-7"},
		{1.2345e-100, "1.2345e-100"},
		{2.2250738585072014e-308, "2.2250738585072014e-308"},
		{5e-324, "5e-324"},
		{math.Pow(2, 53), "9007199254740992"},
		{math.Pow(2, 53) + 2, "9007199254740994"},
		{math.MaxFloat64, "1.7976931348623157e+308"},
		{-math.MaxFloat64, "-1.7976931348623157e+308"},
		{math.Copysign(0, -1), "0"},
		{0, "0"},
	}
	for _, tc := range tests {
		if got := format(t, tc.f); got != tc.want {
			t.Errorf("appendNumber(%v): got %q, want %q", tc.f, got, tc.want)
		}
	}
}

// The output parses back to the same value, for the edge cases and for a
// sweep over exponents: shortest digits never lose information.
func TestAppendNumberRoundTrip(t *testing.T) {
	var vals []float64
	for _, tc := range appendixB {
		vals = append(vals, math.Float64frombits(tc.bits))
	}
	for e := -330; e <= 308; e++ {
		for _, m := range []float64{1, 1.5, 9.999999999999998, 7.123456789012345} {
			v, err := strconv.ParseFloat(strconv.FormatFloat(m, 'f', -1, 64)+"e"+strconv.Itoa(e), 64)
			if errors.Is(err, strconv.ErrRange) && math.IsInf(v, 0) {
				continue // beyond MaxFloat64: not a value to format
			}
			if err != nil {
				t.Fatal(err)
			}
			vals = append(vals, v, -v)
		}
	}
	for _, f := range vals {
		s := format(t, f)
		back, err := strconv.ParseFloat(s, 64)
		if err != nil || back != f {
			t.Errorf("%v -> %q -> %v, %v", f, s, back, err)
		}
	}
}

func TestAppendNumberKeepsPrefix(t *testing.T) {
	b, err := appendNumber([]byte("["), 1.5)
	if err != nil || string(b) != "[1.5" {
		t.Errorf("appendNumber([, 1.5) = %q, %v", b, err)
	}
}

func TestAppendNumberNonFinite(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		b, err := appendNumber([]byte("x"), f)
		if err != errNonFinite {
			t.Errorf("appendNumber(%v) error = %v, want errNonFinite", f, err)
		}
		if string(b) != "x" {
			t.Errorf("appendNumber(%v) changed the buffer to %q", f, b)
		}
	}
}
