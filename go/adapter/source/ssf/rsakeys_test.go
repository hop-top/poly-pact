package ssf_test

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sync"
	"testing"
)

// The RSA test keys of the cases (spec/v1.0/profiles/sources/ssf.md, section 13)
// are derived from a label, so that anyone can recompute them. Like the P-256
// test keys they are public and for tests only.
//
// For a modulus of B bits, each of p and q has b = ceil(B/2) bits. The
// candidate is the first b/8 octets of SHA-256(label 0x00 role 0x00 i) for
// i = 0, 1, ... concatenated, role being "p" or "q" and i four octets
// big-endian; its bit b-1 is set and its bit 0 is set, and, so that the
// modulus has exactly B bits, either bit b-2 too (B even) or bits b-2 to b-4
// cleared (B odd). The prime is the first candidate, stepping by 2, that is
// prime and for which p-1 is not a multiple of e = 65537.

type rsaSpec struct {
	label string
	bits  int
}

var rsaSpecs = map[string]rsaSpec{
	"test-rsa-key-1":    {"ssf-rsa-1", 2048},
	"test-rsa-key-1024": {"ssf-rsa-1024", 1024},
	"test-rsa-key-2047": {"ssf-rsa-2047", 2047},
	"adversarial":       {"ssf-rsa-adversarial", 2048},
}

var (
	rsaMu    sync.Mutex
	rsaCache = map[string]*rsa.PrivateKey{}
)

// rsaKeyOf returns the test key of a kid of rsaSpecs ("adversarial" is the
// forger's key, which has no kid in a key set).
func rsaKeyOf(t testing.TB, name string) *rsa.PrivateKey {
	t.Helper()
	rsaMu.Lock()
	defer rsaMu.Unlock()
	if k, ok := rsaCache[name]; ok {
		return k
	}
	spec, ok := rsaSpecs[name]
	if !ok {
		t.Fatalf("no RSA test key %q", name)
	}
	k := deriveRSA(t, spec.label, spec.bits)
	rsaCache[name] = k
	return k
}

func deriveRSA(t testing.TB, label string, bits int) *rsa.PrivateKey {
	t.Helper()
	b := (bits + 1) / 2
	p := derivePrime(t, label, "p", b, bits%2 == 0)
	q := derivePrime(t, label, "q", b, bits%2 == 0)
	n := new(big.Int).Mul(p, q)
	if n.BitLen() != bits {
		t.Fatalf("%s: modulus of %d bits, want %d", label, n.BitLen(), bits)
	}
	one := big.NewInt(1)
	p1, q1 := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(p1, q1)
	d := new(big.Int).ModInverse(big.NewInt(65537), phi)
	if d == nil {
		t.Fatalf("%s: e is not invertible", label)
	}
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: d, Primes: []*big.Int{p, q}}
	if err := k.Validate(); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	k.Precompute()
	return k
}

func derivePrime(t testing.TB, label, role string, bits int, evenModulus bool) *big.Int {
	t.Helper()
	var buf []byte
	for i := uint32(0); len(buf) < bits/8; i++ {
		h := sha256.New()
		h.Write([]byte(label))
		h.Write([]byte{0})
		h.Write([]byte(role))
		h.Write([]byte{0})
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], i)
		h.Write(c[:])
		buf = h.Sum(buf)
	}
	x := new(big.Int).SetBytes(buf[:bits/8])
	x.SetBit(x, bits-1, 1)
	for _, i := range []int{2, 3, 4} {
		x.SetBit(x, bits-i, 0)
	}
	if evenModulus {
		x.SetBit(x, bits-2, 1)
	}
	x.SetBit(x, 0, 1)
	e, one, two := big.NewInt(65537), big.NewInt(1), big.NewInt(2)
	for ; ; x.Add(x, two) {
		if x.ProbablyPrime(20) && new(big.Int).Mod(new(big.Int).Sub(x, one), e).Sign() != 0 {
			break
		}
	}
	if x.BitLen() != bits || x.Bit(bits-2) == 1 != evenModulus {
		t.Fatalf("%s %s: the search left the band", label, role)
	}
	return x
}
