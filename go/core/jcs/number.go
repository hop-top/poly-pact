package jcs

import (
	"errors"
	"math"
	"strconv"
)

var errNonFinite = errors.New("jcs: non-finite number")

// appendNumber appends f as ECMAScript Number::toString writes it (RFC 8785
// Section 3.2.2.3): NaN and the infinities are an error, zero of either sign
// is "0", and otherwise, with k the number of shortest round-trip digits and
// n the decimal point position (the value is 0.d1d2...dk * 10^n):
//
//	k <= n <= 21     the digits, then n-k zeros
//	0 < n <= 21      the first n digits, ".", the remaining digits
//	-6 < n <= 0      "0.", then -n zeros, then the digits
//	otherwise        d1, then "." and d2...dk when k > 1, then "e", a sign
//	                 that is always written, and the decimal exponent n-1
//	                 without leading zeros
//
// On an error b is returned unchanged.
func appendNumber(b []byte, f float64) ([]byte, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return b, errNonFinite
	}
	if f == 0 {
		return append(b, '0'), nil // also -0
	}
	if f < 0 {
		b = append(b, '-')
		f = -f
	}

	// The shortest digits that round-trip, as d[.ddd]e±dd. strconv puts at
	// least two digits in the exponent and ECMAScript none that are
	// superfluous, so only the digits and the exponent value are taken.
	var scratch [32]byte
	e := strconv.AppendFloat(scratch[:0], f, 'e', -1, 64)
	var digits [24]byte
	k := 0
	i := 0
	for ; e[i] != 'e'; i++ {
		if e[i] != '.' {
			digits[k] = e[i]
			k++
		}
	}
	exp, err := strconv.Atoi(string(e[i+1:])) // "+21" and "-07" parse
	if err != nil {
		return b, err // not reachable: strconv writes a signed integer here
	}
	n := exp + 1
	d := digits[:k]

	switch {
	case k <= n && n <= 21:
		b = append(b, d...)
		for range n - k {
			b = append(b, '0')
		}
	case 0 < n && n <= 21:
		b = append(b, d[:n]...)
		b = append(b, '.')
		b = append(b, d[n:]...)
	case -6 < n && n <= 0:
		b = append(b, '0', '.')
		for range -n {
			b = append(b, '0')
		}
		b = append(b, d...)
	default:
		b = append(b, d[0])
		if k > 1 {
			b = append(b, '.')
			b = append(b, d[1:]...)
		}
		b = append(b, 'e')
		if n-1 < 0 {
			b = append(b, '-')
		} else {
			b = append(b, '+')
		}
		b = strconv.AppendInt(b, int64(abs(n-1)), 10)
	}
	return b, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
