package mtls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"hop.top/pact-go/core/clock"
)

// reasonRemoveFromCRL is the CRL reason code that only delta lists carry
// (RFC 5280, section 5.3.1).
const reasonRemoveFromCRL = 8

// snapshot is the accepted revocation list of one pinned CA (MTLS-12).
type snapshot struct {
	number     *big.Int
	thisUpdate time.Time
	revoked    map[string]bool
}

// ErrListRefused is the error of a revocation list that is not adopted.
var ErrListRefused = errors.New("mtls: revocation list not adopted")

// Adopt accepts der, a revocation list fetched for the pinned CA caID, as the
// snapshot of that CA when it meets every condition of MTLS-12, at the
// adapter's current time. Otherwise it returns an error that wraps
// [ErrListRefused] and the held snapshot, if any, stays unchanged.
func (a *Adapter) Adopt(caID string, der []byte) error {
	entry, ok := a.pinned.Load().byID(caID)
	if !ok {
		return fmt.Errorf("%w: %q is not a pinned ca-id", ErrListRefused, caID)
	}
	if len(der) > a.cfg.MaxCRLBytes {
		return fmt.Errorf("%w: the list is larger than %d octets", ErrListRefused, a.cfg.MaxCRLBytes)
	}
	// A list is DER (MTLS-11); an armored list does not parse.
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrListRefused, err)
	}
	ca := entry.Certificate
	if err := rl.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("%w: signature: %v", ErrListRefused, err)
	}
	if !bytes.Equal(rl.RawIssuer, ca.RawSubject) {
		return fmt.Errorf("%w: the issuer is not the pinned CA's subject", ErrListRefused)
	}
	if len(rl.AuthorityKeyId) > 0 && len(ca.SubjectKeyId) > 0 && !bytes.Equal(rl.AuthorityKeyId, ca.SubjectKeyId) {
		return fmt.Errorf("%w: the authority key identifier is not the CA's key", ErrListRefused)
	}
	now := a.cfg.Clock.Now()
	if rl.ThisUpdate.After(now.Add(clock.BaselineSkew)) {
		return fmt.Errorf("%w: thisUpdate is ahead of the clock", ErrListRefused)
	}
	if rl.NextUpdate.IsZero() || !rl.NextUpdate.After(now) {
		return fmt.Errorf("%w: nextUpdate is absent or passed", ErrListRefused)
	}
	for _, e := range rl.Extensions {
		if e.Critical {
			return fmt.Errorf("%w: critical list extension %v", ErrListRefused, e.Id)
		}
	}
	revoked := make(map[string]bool, len(rl.RevokedCertificateEntries))
	for _, r := range rl.RevokedCertificateEntries {
		for _, e := range r.Extensions {
			if e.Critical {
				return fmt.Errorf("%w: critical entry extension %v", ErrListRefused, e.Id)
			}
		}
		if r.ReasonCode == reasonRemoveFromCRL {
			return fmt.Errorf("%w: an entry carries removeFromCRL", ErrListRefused)
		}
		revoked[r.SerialNumber.String()] = true
	}
	if rl.Number == nil {
		return fmt.Errorf("%w: no CRL number", ErrListRefused)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if held := a.snapshots[caID]; held != nil && rl.Number.Cmp(held.number) <= 0 {
		return fmt.Errorf("%w: CRL number %v is not greater than the held %v", ErrListRefused, rl.Number, held.number)
	}
	a.snapshots[caID] = &snapshot{number: new(big.Int).Set(rl.Number), thisUpdate: rl.ThisUpdate, revoked: revoked}
	return nil
}

// statusOf returns the snapshot of the pinned CA caID that may be used at
// now, the status bound applied (MTLS-14, MTLS-15): nil when there is none or
// the held one is older than the bound.
func (a *Adapter) statusOf(caID string, now time.Time) *snapshot {
	a.mu.Lock()
	s := a.snapshots[caID]
	a.mu.Unlock()
	if s == nil || now.Sub(s.thisUpdate) > a.cfg.StatusBound {
		return nil
	}
	return s
}

// isRevoked applies MTLS-13: the serial, compared as an integer, is listed,
// whatever the reason.
func (s *snapshot) isRevoked(c *x509.Certificate) bool {
	return s.revoked[c.SerialNumber.String()]
}
