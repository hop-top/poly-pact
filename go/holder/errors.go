package holder

import "hop.top/pact-go/adapter"

// The codes of the draft 13.4 table that this package returns and that
// [adapter] has no constant for.
const (
	CodeConflictingEvidence adapter.Code = "CONFLICTING_EVIDENCE"
	CodeExpired             adapter.Code = "EXPIRED"
)

// codeError is a sentinel error that carries a draft 13.4 code.
type codeError struct {
	code adapter.Code
	text string
}

func (e *codeError) Error() string { return "holder: " + e.text }

// Code returns the draft 13.4 code of the error, so that [adapter.CodeOf]
// reads it.
func (e *codeError) Code() adapter.Code { return e.code }

// The sentinel errors. Every error of the package wraps exactly one; an
// error of [hop.top/pact-go/contract] is translated to the sentinel of its
// code, its text kept.
var (
	// ErrInvalidMessage: an input that is not a valid artifact of its type
	// (a contract, evidence or snapshot that does not decode, a typ that
	// does not match its slot), a profile whose lifetime breaks draft 8.1,
	// a presentation over a draft 20.1 limit, or a holder configuration
	// error (INVALID_MESSAGE).
	ErrInvalidMessage error = &codeError{adapter.CodeInvalidMessage, "invalid message or configuration"}

	// ErrUnsupportedVersion: a gateway, contract or embedded artifact names
	// no wire version this holder implements; the holder never downgrades
	// (draft 21). Its code is INVALID_MESSAGE, the 13.4 code of an
	// unsupported structure.
	ErrUnsupportedVersion error = &codeError{adapter.CodeInvalidMessage, "unsupported wire version"}

	// ErrInvalidProof: the publisher's signature does not verify, the key
	// of the key source is not the holder_jkt of the contract or profile,
	// or the key source produced a signature its public key does not
	// verify (INVALID_PROOF, draft 6.2, 11.2).
	ErrInvalidProof error = &codeError{adapter.CodeInvalidProof, "publisher signature or holder key binding failed"}

	// ErrContextMismatch: the contract names another agent, gateway or
	// realm, binds another operation or intent than the one the agent is
	// about to perform, or, in enforced mode, names another transport than
	// the holder's; or the profile names another agent or tenant
	// (CONTEXT_MISMATCH, draft 10.3, 11.2, 13.3.1).
	ErrContextMismatch error = &codeError{adapter.CodeContextMismatch, "agent, gateway, realm, intent or operation differs"}

	// ErrUnsupportedRequirement: the contract carries an extension the
	// holder does not support, which defers (draft 7.1, 21), or the key's
	// algorithm is not negotiated (UNSUPPORTED_REQUIREMENT).
	ErrUnsupportedRequirement error = &codeError{adapter.CodeUnsupportedRequirement, "unsupported extension or algorithm"}

	// ErrMissingField: a field a rule requires has no value the holder may
	// disclose, or an evidence rule has no applicable evidence or snapshot.
	// The holder never replaces a missing authoritative value with a
	// self-asserted one (MISSING_FIELD, draft 8.6, 9.2).
	ErrMissingField error = &codeError{adapter.CodeMissingField, "required field or evidence missing"}

	// ErrConflictingEvidence: the profile value of an evidence rule differs
	// from every applicable authoritative value, or applicable evidence
	// disagrees (CONFLICTING_EVIDENCE, draft 8.4).
	ErrConflictingEvidence error = &codeError{CodeConflictingEvidence, "profile and authoritative values conflict"}

	// ErrExpired: the contract or the profile has expired; there is no
	// grace period (EXPIRED, draft 7.5).
	ErrExpired error = &codeError{CodeExpired, "contract or profile expired"}

	// ErrDependencyUnavailable: the key source or the random source failed
	// (DEPENDENCY_UNAVAILABLE).
	ErrDependencyUnavailable error = &codeError{adapter.CodeDependencyUnavailable, "key source or random source unavailable"}
)
