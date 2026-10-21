// Package jcs canonicalizes JSON as RFC 8785 (JSON Canonicalization Scheme)
// requires, for the object digest of Section 7.4 of the draft. It uses the
// standard library and strictjson only.
//
// Canonicalize reads its input with strictjson, so the checks of Section 7.1
// come first (see that package). It then writes the value the way ECMAScript
// JSON.stringify does, with these rules of RFC 8785 Section 3:
//   - no white space between tokens;
//   - strings: only the quotation mark, the reverse solidus and the control
//     characters below U+0020 are escaped, in the forms of Section 3.2.2.2;
//     every other character, U+007F, U+2028 and U+2029 included, is written
//     as is, and no Unicode normalization is applied;
//   - numbers: IEEE 754 binary64 values in the ECMAScript Number::toString
//     form, with the shortest digits that round-trip (Section 3.2.2.3);
//   - object members are sorted by name, recursively, comparing the names as
//     arrays of UTF-16 code units (Section 3.2.3); array order is kept.
//
// # Number probe
//
// Number formatting is composed from strconv.FormatFloat(f, 'e', -1, 64),
// which gives the shortest round-trip digits, and not from the 'f' or 'g'
// verbs. The probe that settled this ran FormatFloat over the 24 finite
// values of RFC 8785 Appendix B (go1.26.1 darwin/arm64) and compared each with
// the table:
//   - the digits of the 'e' form equal the RFC digits in all 24 cases,
//     including the round-to-even case 43143ff3c1cb0959 (1424953923781206.2)
//     and both sides of the 1e+21 and 1e-6 limits;
//   - the layout does not: the exponent has at least two digits ("1e-06",
//     "9.999999999999997e-07", "0e+00"), minus zero prints as "-0e+00", and a
//     value in the plain range prints in exponent form ("9.007199254740992e+15"
//     for 2^53), so the ECMAScript layout has to be built from the digits and
//     the exponent;
//   - the 'g' form is not the ECMAScript layout either: it switches to
//     exponent form from 1e+06 up and below 1e-04 ("3.333333333333332e+08" for
//     333333333.3333332), and the 'f' form writes 5e-324 with 323 zeros after
//     the decimal point, which ECMAScript writes as "5e-324";
//   - the plus sign of a positive exponent is present in the Go output and
//     must stay: "1e+21", "1e+23" and "1.7976931348623157e+308" in
//     Appendix B, so a formatter that drops it fails those vectors.
//
// With k digits and the decimal point position n (the value is 0.d1...dk times
// 10^n), the layout of ECMA-262 Number::toString applies: k <= n <= 21 prints
// the digits and n-k zeros; 0 < n <= 21 puts the point inside the digits;
// -6 < n <= 0 prints "0." and -n zeros before the digits; otherwise the
// exponent form d1[.d2...dk]e±(n-1) is used, with an explicit sign and no
// leading zeros.
//
// # Vectors
//
// The vectors are the language-neutral files in spec/v1.0/fixtures/vectors/jcs,
// listed in spec/v1.0/fixtures/manifest.json: the six input and output pairs of the
// RFC 8785 reference test data and the first 10000 values of its ECMAScript
// number list, each as an IEEE 754 bit pattern and the expected text.
// vectors_test.go runs every manifest entry whose id starts with "vectors/jcs/".
// The fixture directory has a LICENSE-NOTE.md naming the source and license,
// and the license texts LICENSE.md and LICENSE-2.0.md.
//
// # Limits
//
// Integer literals outside ±(2^53-1) are rejected because strictjson rejects
// them, while a float written with an exponent, such as 1e30, is accepted and
// rounded to binary64 as RFC 8785 test data requires. A float of integer value
// from 2^53 up to 1e21 is therefore written as a plain integer literal, which
// Canonicalize does not accept as input. Digesting an object never feeds
// canonical text back in, so this does not arise there.
package jcs
