package clock

import (
	"errors"
	"fmt"
	"time"
)

// BaselineSkew is the largest clock skew a validator may allow (Section 7.5,
// Section 20.1). There is no expiry grace period in addition to it.
const BaselineSkew = 5 * time.Second

// maxTimestamp is the largest value of a core integer field: 2^53-1
// (Section 7.1).
const maxTimestamp = 1<<53 - 1

// Reasons a check fails. Each error returned by this package wraps exactly one
// of them, so test with errors.Is.
var (
	// ErrSkew: the skew passed to a check is negative or above BaselineSkew.
	ErrSkew = errors.New("clock: skew must be between 0 and 5s")
	// ErrTimestamp: a timestamp is outside 0..2^53-1.
	ErrTimestamp = errors.New("clock: timestamp outside 0..9007199254740991")
	// ErrNotYetValid: nbf is later than now+skew.
	ErrNotYetValid = errors.New("clock: not yet valid (nbf is in the future)")
	// ErrIssuedInFuture: iat is later than now+skew.
	ErrIssuedInFuture = errors.New("clock: issued in the future (iat is later than now plus skew)")
	// ErrExpired: now is at or after exp.
	ErrExpired = errors.New("clock: expired")
	// ErrLifetime: exp is not after iat, or exp-iat is longer than the artifact
	// type allows.
	ErrLifetime = errors.New("clock: invalid lifetime")
	// ErrTooOld: a presentation was issued more than 60 seconds before now.
	ErrTooOld = errors.New("clock: presentation issued more than 60s ago")
	// ErrUnknownArtifact: the Artifact value names no artifact type.
	ErrUnknownArtifact = errors.New("clock: unknown artifact type")
)

// Artifact names an artifact type that Section 20.1 gives a lifetime.
type Artifact int

// The artifact types with a baseline lifetime.
const (
	Presentation Artifact = iota + 1
	Contract
	Evidence
	Snapshot
	Outcome
	Profile
)

func (a Artifact) String() string {
	switch a {
	case Presentation:
		return "presentation"
	case Contract:
		return "requirement contract"
	case Evidence:
		return "evidence"
	case Snapshot:
		return "reputation snapshot"
	case Outcome:
		return "outcome report"
	case Profile:
		return "profile"
	}
	return fmt.Sprintf("Artifact(%d)", int(a))
}

// presentationValidity is the longest presentation lifetime, and the 60 in the
// replay retention formula of Section 7.5.
const presentationValidity = 60 * time.Second

// MaxLifetime returns the longest lifetime of an artifact of type a, measured
// from iat to exp (from created_at to expires_at for a profile).
//
// Section 20.1: presentation 60 s, contract 60 s, evidence 1 h, reputation
// snapshot 300 s, outcome report 300 s, profile 24 h.
func MaxLifetime(a Artifact) (time.Duration, error) {
	switch a {
	case Presentation:
		return presentationValidity, nil
	case Contract:
		return 60 * time.Second, nil
	case Evidence:
		return time.Hour, nil
	case Snapshot, Outcome:
		return 300 * time.Second, nil
	case Profile:
		return 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("%w: %v", ErrUnknownArtifact, a)
}

func checkSkew(skew time.Duration) error {
	if skew < 0 || skew > BaselineSkew {
		return fmt.Errorf("%w: got %v", ErrSkew, skew)
	}
	return nil
}

func checkRange(name string, sec int64) error {
	if sec < 0 || sec > maxTimestamp {
		return fmt.Errorf("%w: %s is %d", ErrTimestamp, name, sec)
	}
	return nil
}

// CheckWindow applies Section 7.5 to an artifact's claims at time now:
//
//	nbf <= now + skew
//	iat <= now + skew
//	now < exp
//
// There is no grace period: an artifact whose exp is at or before now is
// expired, however small the skew. skew must lie in 0..BaselineSkew; a
// deployment that tightens the baseline passes its own smaller value. The
// checks run in the order skew, range, nbf, iat, exp, and the first failure is
// returned.
//
// For an agent profile call CheckWindow(createdAt, createdAt, expiresAt, ...).
func CheckWindow(iat, nbf, exp int64, now time.Time, skew time.Duration) error {
	if err := checkSkew(skew); err != nil {
		return err
	}
	for _, c := range []struct {
		name string
		sec  int64
	}{{"iat", iat}, {"nbf", nbf}, {"exp", exp}} {
		if err := checkRange(c.name, c.sec); err != nil {
			return err
		}
	}
	latest := now.Add(skew)
	if time.Unix(nbf, 0).After(latest) {
		return fmt.Errorf("%w: nbf %d, now %d, skew %v", ErrNotYetValid, nbf, now.Unix(), skew)
	}
	if time.Unix(iat, 0).After(latest) {
		return fmt.Errorf("%w: iat %d, now %d, skew %v", ErrIssuedInFuture, iat, now.Unix(), skew)
	}
	if !now.Before(time.Unix(exp, 0)) {
		return fmt.Errorf("%w: exp %d, now %d", ErrExpired, exp, now.Unix())
	}
	return nil
}

// CheckLifetime reports whether exp-iat is positive (Appendix A.2: iat < exp)
// and no longer than MaxLifetime(a). It compares the claims alone and does not
// need the current time.
func CheckLifetime(a Artifact, iat, exp int64) error {
	max, err := MaxLifetime(a)
	if err != nil {
		return err
	}
	if exp <= iat {
		return fmt.Errorf("%w: %v exp %d is not after iat %d", ErrLifetime, a, exp, iat)
	}
	// exp > iat, so the unsigned difference is exact even when the signed one
	// would overflow.
	if span := uint64(exp) - uint64(iat); span > uint64(max/time.Second) {
		return fmt.Errorf("%w: %v lives %d s, at most %d s", ErrLifetime, a, span, uint64(max/time.Second))
	}
	return nil
}

// CheckPresentationAge reports whether a presentation issued at iat is at most
// 60 seconds old at now: now-iat <= 60 s (Section 7.5). A presentation issued
// ahead of now is not too old; CheckWindow bounds that case.
func CheckPresentationAge(iat int64, now time.Time) error {
	if err := checkRange("iat", iat); err != nil {
		return err
	}
	if now.After(time.Unix(iat, 0).Add(presentationValidity)) {
		return fmt.Errorf("%w: iat %d, now %d", ErrTooOld, iat, now.Unix())
	}
	return nil
}

// CheckPresentation applies every time rule of Section 7.5 to an agent
// presentation: CheckWindow, then exp-iat <= 60 s, then now-iat <= 60 s. The
// first failure is returned. Claims that pass the first two checks always pass
// the third (now < exp <= iat+60); it stays so that each rule is enforced by
// name and survives a change to either bound.
func CheckPresentation(iat, nbf, exp int64, now time.Time, skew time.Duration) error {
	if err := CheckWindow(iat, nbf, exp, now, skew); err != nil {
		return err
	}
	if err := CheckLifetime(Presentation, iat, exp); err != nil {
		return err
	}
	return CheckPresentationAge(iat, now)
}

// ReplayRetention returns the instant before which a replay record must not be
// evicted: the later of the artifact expiry and iat + 60 s + skew (Section
// 7.5). Evicting earlier, even under load, lets a presentation be replayed.
//
// A negative skew counts as zero. Claims outside 0..2^53-1 are clamped into
// that range, which can only lengthen the retention of a valid claim; such
// claims fail CheckWindow before a record is written.
func ReplayRetention(exp, iat int64, skew time.Duration) time.Time {
	skew = max(skew, 0)
	expiry := time.Unix(min(max(exp, 0), maxTimestamp), 0)
	horizon := time.Unix(min(max(iat, 0), maxTimestamp), 0).Add(presentationValidity + skew)
	if expiry.After(horizon) {
		return expiry
	}
	return horizon
}
